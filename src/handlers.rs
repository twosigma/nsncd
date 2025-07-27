/*
 * Copyright 2020-2023 Two Sigma Open Source, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use std::convert::TryInto;
use std::ffi::{CStr, CString};
use std::net::IpAddr;
use std::os::unix::ffi::OsStrExt;

use anyhow::{bail, Context, Result};
use atoi::atoi;
use dns_lookup::AddrInfoHints;
use nix::libc::{AI_CANONNAME, SOCK_STREAM};
use nix::sys::socket::AddressFamily;
use nix::unistd::{getgrouplist, Gid, Group, Uid, User};
use slog::{debug, error, Logger};
use std::mem;
use std::mem::size_of;
use std::num::ParseIntError;
use std::ptr;
use std::str::FromStr;
use std::sync::{LazyLock, Mutex};

use crate::ffi::{gethostbyaddr_r, gethostbyname2_r, Hostent, HostentError, LibcIp};
use crate::protocol::{AiResponse, AiResponseHeader};

use super::config::Config;
use super::protocol;
use super::protocol::RequestType;

use nix::libc::{c_char, c_int, servent, size_t};

mod nixish;
use nixish::{Netgroup, Service};

const ERANGE: i32 = 34;

fn call_with_erange_handling<F>(buf: &mut Vec<c_char>, mut f: F) -> i32
where
    F: FnMut(&mut Vec<c_char>) -> i32,
{
    loop {
        let ret = f(buf);
        if ret == ERANGE {
            if buf.len() > 10 << 20 {
                // Let's not let this get much bigger than 10MB
                return ret;
            }
            buf.resize(buf.len() * 2, 0 as c_char);
        } else {
            return ret;
        }
    }
}

// these functions are not available in the nix::libc crate
extern "C" {
    fn setnetgrent(netgroup: *const c_char) -> i32;
    fn endnetgrent();
    fn getnetgrent_r(
        hostp: *mut *mut c_char,
        userp: *mut *mut c_char,
        domainp: *mut *mut c_char,
        buffer: *mut c_char,
        buflen: size_t,
    ) -> c_int;
    fn innetgr(
        netgroup: *const c_char,
        host: *const c_char,
        user: *const c_char,
        domain: *const c_char,
    ) -> c_int;
    fn getservbyname_r(
        name: *const c_char,
        proto: *const c_char,
        result_buf: *mut servent,
        buf: *mut c_char,
        buflen: size_t,
        result: *mut *mut servent,
    ) -> c_int;
    fn getservbyport_r(
        port: c_int,
        proto: *const c_char,
        result_buf: *mut servent,
        buf: *mut c_char,
        buflen: size_t,
        result: *mut *mut servent,
    ) -> c_int;
}
#[derive(Debug)]
pub struct ServiceWithName {
    pub proto: Option<String>,
    pub service: String,
}
#[derive(Debug)]
pub struct ServiceWithPort {
    pub proto: Option<String>,
    pub port: u16,
}

#[derive(Debug)]
pub struct NetgroupWithName {
    pub name: String,
}
#[derive(Debug, PartialEq)]
pub struct InNetGroup {
    pub netgroup: String,
    pub host: Option<String>,
    pub user: Option<String>,
    pub domain: Option<String>,
}

impl FromStr for ServiceWithName {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split('/').collect();

        if parts.len() != 2 {
            return Err("Input must be in the format 'service/proto'".into());
        }

        let service = parts[0].to_owned();
        let proto = if parts[1].is_empty() {
            None
        } else {
            Some(parts[1].to_owned())
        };

        Ok(ServiceWithName { proto, service })
    }
}

impl ServiceWithName {
    fn lookup(&self) -> Result<Option<Service>> {
        let service_name = CString::new(self.service.clone())?;
        let proto = match &self.proto {
            Some(p) => Some(CString::new(p.clone())?),
            None => None,
        };

        let mut result_buf: servent = unsafe { mem::zeroed() };
        let mut buffer: Vec<c_char> = vec![0; 1024];
        let mut result: *mut servent = ptr::null_mut();

        let ret = call_with_erange_handling(&mut buffer, |buffer| unsafe {
            getservbyname_r(
                service_name.as_ptr(),
                proto.as_ref().map_or(ptr::null(), |p| p.as_ptr()),
                &mut result_buf,
                buffer.as_mut_ptr(),
                buffer.len(),
                &mut result,
            )
        });
        // lookup was successful
        if ret == 0 {
            if !result.is_null() {
                let service: Service = unsafe { *result }.try_into()?;
                Ok(Some(service))
            } else {
                Ok(None)
            }
        } else {
            anyhow::bail!("Error: getservbyname_r failed with code {}", ret);
        }
    }
}

impl FromStr for ServiceWithPort {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split('/').collect();

        if parts.len() != 2 {
            return Err("Input must be in the format 'port/proto'".into());
        }

        let port: u16 = parts[0]
            .parse()
            .map_err(|err: ParseIntError| err.to_string())?;
        let proto = if parts[1].is_empty() {
            None
        } else {
            Some(parts[1].to_owned())
        };

        Ok(ServiceWithPort { proto, port })
    }
}

impl ServiceWithPort {
    fn lookup(&self) -> Result<Option<Service>> {
        //issue-142
        //port 0 lookups to sssd return ENOMEM
        if self.port == 0 {
            return Ok(None);
        }
        let proto = match &self.proto {
            Some(p) => Some(CString::new(p.clone())?),
            None => None,
        };

        let mut result_buf: servent = unsafe { mem::zeroed() };
        let mut buffer: Vec<c_char> = vec![0; 1024];
        let mut result: *mut servent = ptr::null_mut();

        let ret = call_with_erange_handling(&mut buffer, |buffer| unsafe {
            getservbyport_r(
                self.port as c_int,
                proto.as_ref().map_or(ptr::null(), |p| p.as_ptr()),
                &mut result_buf,
                buffer.as_mut_ptr(),
                buffer.len(),
                &mut result,
            )
        });
        if ret == 0 {
            if !result.is_null() {
                let service: Service = unsafe { *result }.try_into()?;
                Ok(Some(service))
            } else {
                Ok(None)
            }
        } else {
            anyhow::bail!("Error: getservbyport_r failed with code {}", ret);
        }
    }
}

impl InNetGroup {
    pub fn from_bytes(bytes: &[u8]) -> Result<InNetGroup> {
        let mut args: [Option<String>; 3] = [None, None, None];

        /*
        For innegroup -h h -u u -d d netgroup the input bytes string looks like this
        6e 65 74 67 72 6f 75 70 00 01 68 00 01 75 00 01 64 00
                                       h        u        d
        The host, user, domain arguments are always in the same order
        Split the input by nul byte, generate strings as appropriate, skipping the SOH byte
        */

        let parts: Vec<&[u8]> = bytes.split(|&b| b == 0).collect();

        // netgroup is always present
        let netgroup = if let Ok(string) = std::str::from_utf8(parts[0]) {
            string.to_string()
        } else {
            anyhow::bail!("Parsing of netgroup failed");
        };

        // The remainder are optional
        // if len 0, just a NUL char
        // else, SOH char followed by arg, skip element 0 when making the string
        for idx in 0..3 {
            if !parts[idx + 1].is_empty() {
                args[idx] = if let Ok(string) = std::str::from_utf8(&parts[idx + 1][1..]) {
                    Some(string.to_string())
                } else {
                    None
                };
            }
        }

        Ok(InNetGroup {
            netgroup,
            host: args[0].clone(),
            user: args[1].clone(),
            domain: args[2].clone(),
        })
    }

    fn lookup(&self) -> Result<bool> {
        let netgroup_name = CString::new(self.netgroup.clone())?;

        let host = match &self.host {
            Some(s) => Some(CString::new(s.clone())?),
            None => None,
        };
        let user = match &self.user {
            Some(s) => Some(CString::new(s.clone())?),
            None => None,
        };
        let domain = match &self.domain {
            Some(s) => Some(CString::new(s.clone())?),
            None => None,
        };

        let ret = unsafe {
            innetgr(
                netgroup_name.as_ptr() as *const c_char,
                host.as_ref().map_or(ptr::null(), |s| s.as_ptr()),
                user.as_ref().map_or(ptr::null(), |s| s.as_ptr()),
                domain.as_ref().map_or(ptr::null(), |s| s.as_ptr()),
            ) != 0
        };
        Ok(ret)
    }
}

impl FromStr for NetgroupWithName {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let name = s.to_owned();

        Ok(NetgroupWithName { name })
    }
}

//Required for use of setnetgrent in multi threaded apps
//https://docs.oracle.com/cd/E88353_01/html/E37843/setnetgrent-3c.html

//Note that while setnetgrent() and endnetgrent() are safe for use in multi-threaded applications, the effect of each is process-wide.
//Calling setnetgrent() resets the enumeration position for all threads.
//If multiple threads interleave calls to getnetgrent_r() each will enumerate a disjoint subset of the netgroup.
//Thus the effective use of these functions in multi-threaded applications may require coordination by the caller.

//Make a Mutex to ensure that setnetgrent and getnetgrent_r are called in sequence
static SETNETGRENT_LOCK: LazyLock<Mutex<u8>> = LazyLock::new(|| Mutex::new(0));
impl NetgroupWithName {
    fn lookup(&self) -> Result<Vec<Netgroup>> {
        let mut results: Vec<Netgroup> = vec![];

        let netgroup_name = CString::new(self.name.clone())?;

        // if the mutex thinks it was poisoned (e.g by a thread panicing)
        // that thread is not running, thus we can take the lock
        // There is no need to explicitly unlock, this happens automatically
        // at the conclusion of the function
        let _guard = match SETNETGRENT_LOCK.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };

        if unsafe { setnetgrent(netgroup_name.as_ptr() as *const c_char) } != 1 {
            //setnetgrent returns 0 if the netgroup cannot be found
            return Ok(results);
        }
        let mut buffer = vec![0 as c_char; 4096];
        let mut host: *mut c_char = std::ptr::null_mut();
        let mut user: *mut c_char = std::ptr::null_mut();
        let mut domain: *mut c_char = std::ptr::null_mut();

        loop {
            let ret = call_with_erange_handling(&mut buffer, |buffer| unsafe {
                getnetgrent_r(
                    &mut host,
                    &mut user,
                    &mut domain,
                    buffer.as_mut_ptr(),
                    buffer.len() as size_t,
                )
            });
            if ret == 1 {
                let host_str = if !host.is_null() {
                    Some(unsafe { CStr::from_ptr(host) }.to_owned())
                } else {
                    None
                };
                let user_str = if !user.is_null() {
                    Some(unsafe { CStr::from_ptr(user) }.to_owned())
                } else {
                    None
                };
                let domain_str = if !domain.is_null() {
                    Some(unsafe { CStr::from_ptr(domain) }.to_owned())
                } else {
                    None
                };

                results.push(Netgroup {
                    host: host_str,
                    user: user_str,
                    domain: domain_str,
                });

                continue;
            } else if ret == 0 {
                unsafe { endnetgrent() };
                break;
            } else {
                // Handle other errors
                anyhow::bail!("Error: getnetgrent_r failed with code {}", ret);
            }
        }

        Ok(results)
    }
}

/// Handle a request by performing the appropriate lookup and sending the
/// serialized response back to the client.
///
/// # Arguments
///
/// * `log` - A `slog` Logger.
/// * `config` - The nsncd configuration (which request types to ignore).
/// * `request` - The request to handle.
pub fn handle_request(
    log: &Logger,
    config: &Config,
    request: &protocol::Request,
) -> Result<Vec<u8>> {
    if config.should_ignore(&request.ty) {
        debug!(log, "ignoring request"; "request" => ?request);
        return Ok(vec![]);
    }
    debug!(log, "handling request"; "request" => ?request);
    match request.ty {
        RequestType::GETPWBYUID => {
            let key = CStr::from_bytes_with_nul(request.key)?;
            let uid = atoi(key.to_bytes()).context("invalid uid string")?;
            let user = User::from_uid(Uid::from_raw(uid))?;
            debug!(log, "got user"; "user" => ?user);
            serialize_user(user)
        }
        RequestType::GETPWBYNAME => {
            let key = CStr::from_bytes_with_nul(request.key)?;
            let user = User::from_name(key.to_str()?)?;
            debug!(log, "got user"; "user" => ?user);
            serialize_user(user)
        }
        RequestType::GETGRBYGID => {
            let key = CStr::from_bytes_with_nul(request.key)?;
            let gid = atoi(key.to_bytes()).context("invalid gid string")?;
            let group = Group::from_gid(Gid::from_raw(gid))?;
            debug!(log, "got group"; "group" => ?group);
            serialize_group(group)
        }
        RequestType::GETGRBYNAME => {
            let key = CStr::from_bytes_with_nul(request.key)?;
            let group = Group::from_name(key.to_str()?)?;
            debug!(log, "got group"; "group" => ?group);
            serialize_group(group)
        }
        RequestType::INITGROUPS => {
            // initgroups is a little strange: in the public libc API, the
            // interface is getgrouplist(), which requires that you pass one
            // extra GID (intended to be the user's primary GID) in, which is
            // returned as part of the result. In the glibc NSS implementation,
            // NSS backends can implement initgroups_dyn(), which is not
            // expected to find the primary GID (for example,
            // _nss_files_initgroups_dyn() only looks at /etc/group);
            // alternatively, both glibc itself and its NSCD implementation will
            // fall back to enumerating all groups with getgrent(). It will then
            // tack on the provided GID before returning, if it's not already in
            // the list.
            //
            // There's no public API to just get the supplementary groups, so we
            // need to get the primary group and pass it to getgrouplist()
            // (since we don't want to implement the NSS API ourselves).
            //
            // One corollary is that getting supplementary groups never fails;
            // if you ask for a nonexistent user, they just happen not to be in
            // any groups. So the "found" value is mostly used to indicate
            // whether the response is valid - in other words, we return found =
            // 1 and an empty list if User::from_name fails, meaning the
            // client can be happy with the response we provide.
            //
            // nix::getgrouplist can fail, in theory, if the number of groups is
            // greater than NGROUPS_MAX. (On Linux this is 65536 and therefore
            // pretty unlikely in practice.) There are only two things we can do
            // here: return a false reply or refuse the lookup. (Even if we
            // return found=0, glibc appears to treat that just like found=1
            // ngrps=0, i.e., successful empty reply. It would be useful for
            // glibc to fall back to NSS here, but it does not.) If we refuse
            // the lookup, glibc caches the fact that we don't support
            // INITGROUPS - and uses the same variable for whether we support
            // GETGR*, which causes the process to skip nsncd for all future
            // lookups. So, in this theoretical case, we log our perfidy and
            // return an empty list.
            let key = CStr::from_bytes_with_nul(request.key)?;
            let user = User::from_name(key.to_str()?)?;
            debug!(log, "got user"; "user" => ?user);
            let groups = if let Some(user) = user {
                getgrouplist(key, user.gid).unwrap_or_else(|e| {
                    error!(log, "nix::getgrouplist failed, returning empty list"; "err" => %e);
                    vec![]
                })
            } else {
                vec![]
            };
            serialize_initgroups(groups)
        }

        // There's no cache to invalidate
        RequestType::INVALIDATE => {
            debug!(log, "received invalidate request, ignoring");
            Ok(vec![])
        }

        // We don't want clients to be able to shut down nsncd.
        RequestType::SHUTDOWN => {
            debug!(log, "received shutdown request, ignoring");
            Ok(vec![])
        }

        RequestType::GETAI => {
            let hostname = CStr::from_bytes_with_nul(request.key)?.to_str()?;
            // Boths hints are necessary to mimick the glibc behaviour.
            let hints = AddrInfoHints {
                // The canonical name will be filled in the first
                // addrinfo struct returned by getaddrinfo.
                flags: AI_CANONNAME,
                // There's no way to convey socktype in the the Nscd
                // protocol, neither in the request nor response.
                //
                // Set this to SOCK_STREAM to match glibc and unscd
                // behaviour.
                socktype: SOCK_STREAM,
                address: 0,
                protocol: 0,
            };
            let resp = dns_lookup::getaddrinfo(Some(hostname), None, Some(hints));
            let ai_resp_empty = AiResponse {
                canon_name: hostname.to_string(),
                addrs: vec![],
            };
            let ai_resp: AiResponse = match resp {
                Ok(ai_resp_iter) => {
                    let mut ai_resp_iter = ai_resp_iter.filter_map(|e| e.ok()).peekable();
                    // According to man 3 getaddrinfo, the resulting
                    // canonical name should be stored in the first
                    // addrinfo struct.
                    // Re-using the request hostname if we don't get a
                    // canonical name.
                    let canon_name = ai_resp_iter
                        .peek()
                        .and_then(|e| e.canonname.to_owned())
                        .unwrap_or(hostname.to_string());
                    let addrs: Vec<IpAddr> = ai_resp_iter.map(|e| e.sockaddr.ip()).collect();

                    AiResponse { canon_name, addrs }
                }
                Err(_) => ai_resp_empty,
            };

            serialize_address_info(ai_resp)
        }

        // GETHOSTBYADDR and GETHOSTBYADDRv6 implement reverse lookup
        // The key contains the address to look for.
        RequestType::GETHOSTBYADDR => {
            let key = request.key;

            if key.len() != 4 {
                bail!("Invalid key len: {}, expected 4", key.len());
            }
            let address_bytes: [u8; 4] = key.try_into()?;
            let hostent = match gethostbyaddr_r(LibcIp::V4(address_bytes)) {
                Ok(hostent) => hostent,
                Err(HostentError::HError(herror)) => Hostent::error_value(herror),
                Err(HostentError::Other(e)) =>
                // We shouldn't end up in that branch. Something
                // got very very wrong on the glibc client side if
                // we do. It's okay to bail, there's nothing much
                // we can do.
                {
                    bail!("unexpected gethostbyaddr error: {}", e)
                }
            };

            serialize_hostent(hostent)
        }
        RequestType::GETHOSTBYADDRv6 => {
            let key = request.key;

            if key.len() != 16 {
                bail!("Invalid key len: {}, expected 16", key.len());
            }
            let address_bytes: [u8; 16] = key.try_into()?;
            let hostent = match gethostbyaddr_r(LibcIp::V6(address_bytes)) {
                Ok(hostent) => hostent,
                Err(HostentError::HError(herror)) => Hostent::error_value(herror),
                Err(HostentError::Other(e)) =>
                // We shouldn't end up in that branch. Something
                // got very very wrong on the glibc client side if
                // we do. It's okay to bail, there's nothing much
                // we can do.
                {
                    bail!("unexpected gethostbyaddrv6 error: {}", e)
                }
            };
            serialize_hostent(hostent)
        }

        RequestType::GETHOSTBYNAME => {
            let hostname = CStr::from_bytes_with_nul(request.key)?.to_str()?;
            let hostent = match gethostbyname2_r(hostname.to_string(), nix::libc::AF_INET) {
                Ok(hostent) => hostent,
                Err(HostentError::HError(herror)) => Hostent::error_value(herror),
                Err(HostentError::Other(e)) =>
                // We shouldn't end up in that branch. Something
                // got very very wrong on the glibc client side if
                // we do. It's okay to bail, there's nothing much
                // we can do.
                {
                    bail!("unexpected gethostbyname error: {:?}", e)
                }
            };
            serialize_hostent(hostent)
        }

        RequestType::GETHOSTBYNAMEv6 => {
            let hostname = CStr::from_bytes_with_nul(request.key)?.to_str()?;
            let hostent = match gethostbyname2_r(hostname.to_string(), nix::libc::AF_INET6) {
                Ok(hostent) => hostent,
                Err(HostentError::HError(herror)) => Hostent::error_value(herror),
                Err(HostentError::Other(e)) =>
                // We shouldn't end up in that branch. Something
                // got very very wrong on the glibc client side if
                // we do. It's okay to bail, there's nothing much
                // we can do.
                {
                    bail!("unexpected gethostbynamev6 error: {:?}", e)
                }
            };
            serialize_hostent(hostent)
        }

        RequestType::GETSERVBYNAME => {
            /*
            Sample requests
            $ getent services biff
            biff                  512/udp comsat
            $ getent services exec
            exec                  512/tcp
            $ getent services exec/tcp
            exec                  512/tcp
            $ getent services exec/udp
            $
             */

            //CStr is a borrowed reference to a CStyle string
            //Is is immutable, null terminated, string slice
            //CStr is used as the input is coming from a c ffi function
            let key = CStr::from_bytes_with_nul(request.key)?;
            let str_slice = key.to_str()?;
            // Use the FromStr trait
            match str_slice.parse::<ServiceWithName>() {
                Ok(service_with_name) => {
                    debug!(log, "got getservbyname {:?}", service_with_name);
                    let service = service_with_name.lookup()?;
                    serialize_service(service)
                }
                Err(_e) => {
                    anyhow::bail!("Could not parse service request");
                }
            }
        }
        RequestType::GETSERVBYPORT => {
            /*
            Sample requests
            $ getent services 512
            exec                  512/tcp
            $ getent services 512/tcp
            exec                  512/tcp
            $ getent services 512/udp
            biff                  512/udp comsat

            If /proto is not provided, defaults to tcp

            When the request is received over the socket, the port is in network order

            */
            let key = CStr::from_bytes_with_nul(request.key)?;
            let str_slice: &str = key.to_str()?;
            // Use the FromStr trait
            match str_slice.parse::<ServiceWithPort>() {
                Ok(service_with_port) => {
                    debug!(log, "got getservbyport {:?}", service_with_port);
                    let service = service_with_port.lookup()?;
                    serialize_service(service)
                }
                Err(_e) => {
                    anyhow::bail!("Could not parse service request");
                }
            }
        }
        RequestType::GETNETGRENT => {
            let key = CStr::from_bytes_with_nul(request.key)?;
            let str_slice: &str = key.to_str()?;

            debug!(log, "got netgroup"; "netgroup" => ?key.to_str());

            match str_slice.parse::<NetgroupWithName>() {
                Ok(netgroup_with_name) => {
                    let netgroups = netgroup_with_name.lookup()?;
                    serialize_netgroup(netgroups)
                }
                Err(_e) => {
                    anyhow::bail!("Could not parse netgroup request");
                }
            }
        }
        RequestType::INNETGR => {
            let in_netgroup = InNetGroup::from_bytes(request.key)?;
            debug!(log, "got innetgr {:?}", in_netgroup);
            serialize_innetgr(in_netgroup.lookup()?)
        }

        // These will normally send an FD pointing to the internal cache structure,
        // which clients use to look into the cache contents on their own.
        // We don't cache, and we don't want clients to poke around in cache structures either.
        // Luckily clients fall back to explicit queries if no FDs are sent over.
        RequestType::GETFDPW
        | RequestType::GETFDGR
        | RequestType::GETFDHST
        | RequestType::GETFDSERV
        | RequestType::GETFDNETGR => {
            debug!(log, "received GETFD* request, ignoring");
            Ok(vec![])
        }
        // Not implemented (yet)
        RequestType::GETSTAT | RequestType::LASTREQ => Ok(vec![]),
    }
}

fn serialize_innetgr(innetgr: bool) -> Result<Vec<u8>> {
    let mut result = vec![];

    if innetgr {
        let header = protocol::InNetgroupResponseHeader {
            version: protocol::VERSION,
            found: 1,
            result: 1,
        };
        result.extend_from_slice(header.as_slice());
    }
    Ok(result)
}

//Take a list of NixNetGroup objects and serialize to send back
fn serialize_netgroup(netgroups: Vec<Netgroup>) -> Result<Vec<u8>> {
    let mut result = vec![];

    // first we need to count the size of the return data to populate the header
    let mut result_len: i32 = 0;
    let mut field_len: i32;
    for netgroup in netgroups.iter() {
        if let Some(host) = &netgroup.host {
            field_len = host.to_bytes_with_nul().len().try_into()?;
            result_len += field_len;
        } else {
            result_len += 1;
        }
        if let Some(user) = &netgroup.user {
            field_len = user.to_bytes_with_nul().len().try_into()?;
            result_len += field_len;
        } else {
            result_len += 1;
        }
        if let Some(domain) = &netgroup.domain {
            field_len = domain.to_bytes_with_nul().len().try_into()?;
            result_len += field_len;
        } else {
            result_len += 1;
        }
    }

    // make the header first
    // This approach supports a 0 length list
    let header = protocol::NetgroupResponseHeader {
        version: protocol::VERSION,
        found: 1,
        nresults: netgroups.len().try_into()?,
        result_len,
    };
    // TODO - this should if netgroups.len() ==0 return [].. at the top.
    // not sure of the syntax to early return
    if !netgroups.is_empty() {
        result.extend_from_slice(header.as_slice());
    }

    //send all the results
    //netgroup all, 11641 members appears to work
    let null_string: &[u8] = b"\0";
    for netgroup in netgroups.iter() {
        // TODO - another loop and getattr style

        if let Some(host) = &netgroup.host {
            result.extend_from_slice(host.to_bytes_with_nul());
        } else {
            result.extend_from_slice(null_string);
        }
        if let Some(user) = &netgroup.user {
            result.extend_from_slice(user.to_bytes_with_nul());
        } else {
            result.extend_from_slice(null_string);
        }
        if let Some(domain) = &netgroup.domain {
            result.extend_from_slice(domain.to_bytes_with_nul());
        } else {
            result.extend_from_slice(null_string);
        }
    }
    Ok(result)
}

/// Send a service entry back to the client, or a response indicating the
/// lookup found no such service.
fn serialize_service(service: Option<Service>) -> Result<Vec<u8>> {
    let mut result = vec![];

    if let Some(data) = service {
        let name = CString::new(data.name)?;
        let name_bytes = name.to_bytes_with_nul();

        let proto = CString::new(data.proto)?;
        let proto_bytes = proto.to_bytes_with_nul();

        let port = data.port;

        let aliases: Vec<CString> = data
            .aliases
            .iter()
            .map(|alias| CString::new((*alias).as_bytes()))
            .collect::<Result<Vec<CString>, _>>()?;
        let aliases_bytes: Vec<&[u8]> = aliases
            .iter()
            .map(|alias| alias.to_bytes_with_nul())
            .collect();

        let header = protocol::ServResponseHeader {
            version: protocol::VERSION,
            found: 1,
            s_name_len: name_bytes.len().try_into()?,
            s_proto_len: proto_bytes.len().try_into()?,
            s_aliases_cnt: aliases.len().try_into()?,
            s_port: port,
        };
        result.extend_from_slice(header.as_slice());
        result.extend_from_slice(name_bytes);
        result.extend_from_slice(proto_bytes);
        // first indicate the length of each subsequent alias
        for alias_bytes in aliases_bytes.iter() {
            result.extend_from_slice(&i32::to_ne_bytes(alias_bytes.len().try_into()?));
        }
        // serialize the value of the string
        for alias_bytes in aliases_bytes.iter() {
            result.extend_from_slice(alias_bytes);
        }
    } else {
        let header = protocol::ServResponseHeader::default();
        result.extend_from_slice(header.as_slice());
    }
    Ok(result)
}

/// Send a user (passwd entry) back to the client, or a response indicating the
/// lookup found no such user.
fn serialize_user(user: Option<User>) -> Result<Vec<u8>> {
    let mut result = vec![];
    if let Some(data) = user {
        let name = CString::new(data.name)?;
        let name_bytes = name.to_bytes_with_nul();
        let passwd_bytes = data.passwd.to_bytes_with_nul();
        let gecos_bytes = data.gecos.to_bytes_with_nul();
        let dir = CString::new(data.dir.as_os_str().as_bytes())?;
        let dir_bytes = dir.to_bytes_with_nul();
        let shell = CString::new(data.shell.as_os_str().as_bytes())?;
        let shell_bytes = shell.to_bytes_with_nul();

        let header = protocol::PwResponseHeader {
            version: protocol::VERSION,
            found: 1,
            pw_name_len: name_bytes.len().try_into()?,
            pw_passwd_len: passwd_bytes.len().try_into()?,
            pw_uid: data.uid.as_raw(),
            pw_gid: data.gid.as_raw(),
            pw_gecos_len: gecos_bytes.len().try_into()?,
            pw_dir_len: dir_bytes.len().try_into()?,
            pw_shell_len: shell_bytes.len().try_into()?,
        };
        result.extend_from_slice(header.as_slice());
        result.extend_from_slice(name_bytes);
        result.extend_from_slice(passwd_bytes);
        result.extend_from_slice(gecos_bytes);
        result.extend_from_slice(dir_bytes);
        result.extend_from_slice(shell_bytes);
    } else {
        let header = protocol::PwResponseHeader::default();
        result.extend_from_slice(header.as_slice());
    }
    Ok(result)
}

/// Send a group (group entry) back to the client, or a response indicating the
/// lookup found no such group.
fn serialize_group(group: Option<Group>) -> Result<Vec<u8>> {
    let mut result = vec![];
    if let Some(data) = group {
        let name = CString::new(data.name)?;
        let name_bytes = name.to_bytes_with_nul();
        let mem_cnt = data.mem.len();
        let passwd_bytes = data.passwd.to_bytes_with_nul();
        let members: Vec<CString> = data
            .mem
            .into_iter()
            .map(CString::new)
            .collect::<Result<Vec<CString>, _>>()?;
        let members_bytes: Vec<&[u8]> = members
            .iter()
            .map(|member| member.to_bytes_with_nul())
            .collect();

        let header = protocol::GrResponseHeader {
            version: protocol::VERSION,
            found: 1,
            gr_name_len: name_bytes.len().try_into()?,
            gr_passwd_len: passwd_bytes.len().try_into()?,
            gr_gid: data.gid.as_raw(),
            gr_mem_cnt: mem_cnt.try_into()?,
        };
        result.extend_from_slice(header.as_slice());
        for member_bytes in members_bytes.iter() {
            result.extend_from_slice(&i32::to_ne_bytes(member_bytes.len().try_into()?));
        }
        result.extend_from_slice(name_bytes);
        result.extend_from_slice(passwd_bytes);
        for member_bytes in members_bytes.iter() {
            result.extend_from_slice(member_bytes);
        }
    } else {
        let header = protocol::GrResponseHeader::default();
        result.extend_from_slice(header.as_slice());
    }
    Ok(result)
}

/// Send a user's group list (initgroups/getgrouplist response) back to the
/// client.
fn serialize_initgroups(groups: Vec<Gid>) -> Result<Vec<u8>> {
    let mut result = vec![];
    let header = protocol::InitgroupsResponseHeader {
        version: protocol::VERSION,
        found: 1,
        ngrps: groups.len().try_into()?,
    };

    result.extend_from_slice(header.as_slice());
    for group in groups.iter() {
        result.extend_from_slice(&i32::to_ne_bytes(group.as_raw().try_into()?));
    }

    Ok(result)
}

fn serialize_hostent(hostent: Hostent) -> Result<Vec<u8>> {
    // Loop over all addresses.
    // Serialize them into a slice, which is used later in the payload.
    // Take note of the number of addresses (by AF).
    let mut num_v4 = 0;
    let mut num_v6 = 0;
    let mut buf_addrs = vec![];
    let mut buf_aliases = vec![];
    // Memory segment used to convey the size of the different
    // aliases. The sizes are expressed in native endian encoded 32
    // bits integer.
    let mut buf_aliases_size = vec![];

    for address in hostent.addr_list.iter() {
        match address {
            IpAddr::V4(ip4) => {
                num_v4 += 1;
                for octet in ip4.octets() {
                    buf_addrs.push(octet)
                }
            }
            IpAddr::V6(ip6) => {
                num_v6 += 1;
                for octet in ip6.octets() {
                    buf_addrs.push(octet)
                }
            }
        }
    }

    // this can only ever express one address family
    if num_v4 != 0 && num_v6 != 0 {
        bail!("unable to serialize mixed AF")
    }

    // if there's no addresses, early-return the "empty result" response.
    if hostent.addr_list.is_empty() {
        return Ok(Vec::from(
            protocol::HstResponseHeader {
                version: protocol::VERSION,
                found: 0,
                h_name_len: 0,
                h_aliases_cnt: 0,
                h_addrtype: -1,
                h_length: -1,
                h_addr_list_cnt: 0,
                error: hostent.herrno,
            }
            .as_slice(),
        ));
    }

    for alias in hostent.aliases.iter() {
        buf_aliases_size.extend_from_slice(&(alias.as_bytes_with_nul().len() as i32).to_ne_bytes());
        buf_aliases.extend_from_slice(alias.as_bytes_with_nul());
    }

    let hostname_bytes = hostent.name.into_bytes_with_nul();

    let header = protocol::HstResponseHeader {
        version: protocol::VERSION,
        found: 1,
        h_name_len: hostname_bytes.len() as i32,
        h_aliases_cnt: hostent.aliases.len() as i32,
        h_addrtype: if num_v4 != 0 {
            nix::sys::socket::AddressFamily::Inet as i32
        } else {
            nix::sys::socket::AddressFamily::Inet6 as i32
        },
        h_length: if num_v4 != 0 { 4 } else { 16 },
        h_addr_list_cnt: hostent.addr_list.len() as i32,
        error: hostent.herrno,
    };

    let total_len = std::mem::size_of::<protocol::HstResponseHeader>()
        + hostname_bytes.len()
        + buf_addrs.len()
        + buf_aliases.len()
        + buf_aliases_size.len();

    let mut buf = Vec::with_capacity(total_len);

    // add header
    buf.extend_from_slice(header.as_slice());

    // add hostname
    buf.extend_from_slice(&hostname_bytes);

    // add aliases sizes
    buf.extend_from_slice(buf_aliases_size.as_slice());

    // add serialized addresses from buf_addrs
    buf.extend_from_slice(buf_addrs.as_slice());

    // add aliases
    buf.extend_from_slice(buf_aliases.as_slice());

    debug_assert_eq!(buf.len(), total_len);

    Ok(buf)
}

/// Serialize a [RequestType::GETAI] response to the wire.
///
/// This wire format has been implemented by reading the `addhstaiX`
/// function living in the `nscd/aicache.c` glibc file. We copy the
/// exact same behaviour, aside from the caching part.
///
/// The wire getaddrinfo call result is serialized like this:
///
/// 1. version: int32. Hardcoded to 2.
/// 2. found: int32. 1 if we have a result, 0 if we don't.
/// 3. naddrs: int32. Number of IPv4/6 adresses we're about to write.
/// 4. addrslen: int32. Total length of the IPv4/6 adresses we're
///    about to write.
/// 5. canonlen: int32. Total length of the null-terminated canonical
///    name string.
/// 6. error: int32. Error code. Always 0 in the current nscd impl
/// 7. addrs: \[BE-encoded IPv4/IPv6\]. We sequentially write the
///    IPv4 and IPv6 bytes using a big endian encoding. There's no
///    padding, an IPv4 will be 4 bytes wide, an IPv6 16 bytes wide.
/// 8. addr_family: \[uint8\]. This array mirrors the addrs array. Each
///    addr element will be mirrored in this array, except we'll write
///    the associated IP addr family number. AF_INET for an IPv4,
///    AF_INET6 for a v6.
/// 9. canon_name: Canonical name of the host. Null-terminated string.
fn serialize_address_info(resp: AiResponse) -> Result<Vec<u8>> {
    let mut b_families: Vec<u8> = Vec::with_capacity(2);
    let mut b_addrs: Vec<u8> = Vec::with_capacity(2);
    for addr in &resp.addrs {
        match addr {
            IpAddr::V4(ip) => {
                b_families.push(AddressFamily::Inet as u8);
                b_addrs.extend(ip.octets())
            }
            IpAddr::V6(ip) => {
                b_families.push(AddressFamily::Inet6 as u8);
                b_addrs.extend(ip.octets())
            }
        }
    }
    let addrslen = b_addrs.len();
    if addrslen > 0 {
        let b_canon_name = CString::new(resp.canon_name)?.into_bytes_with_nul();
        let ai_response_header = AiResponseHeader {
            version: protocol::VERSION,
            found: 1,
            naddrs: resp.addrs.len() as i32,
            addrslen: addrslen as i32,
            canonlen: b_canon_name.len() as i32,
            error: protocol::H_ERRNO_NETDB_SUCCESS,
        };

        let total_len = size_of::<AiResponseHeader>() + b_addrs.len() + b_families.len();
        let mut buffer = Vec::with_capacity(total_len);
        buffer.extend_from_slice(ai_response_header.as_slice());
        buffer.extend_from_slice(&b_addrs);
        buffer.extend_from_slice(&b_families);
        buffer.extend_from_slice(&b_canon_name);
        Ok(buffer)
    } else {
        let mut buffer = Vec::with_capacity(size_of::<AiResponseHeader>());
        buffer.extend_from_slice(protocol::AI_RESPONSE_HEADER_NOT_FOUND.as_slice());
        Ok(buffer)
    }
}

#[cfg(test)]
mod test {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use nix::libc::{AF_INET, AF_INET6};

    use super::*;

    fn test_logger() -> slog::Logger {
        Logger::root(slog::Discard, slog::o!())
    }

    #[test]
    fn test_handle_request_empty_key() {
        let request = protocol::Request {
            ty: protocol::RequestType::GETPWBYNAME,
            key: &[],
        };

        let result = handle_request(&test_logger(), &Config::default(), &request);
        assert!(result.is_err(), "should error on empty input");
    }

    #[test]
    fn test_handle_request_nul_data() {
        let request = protocol::Request {
            ty: protocol::RequestType::GETPWBYNAME,
            key: &[0x7F, 0x0, 0x0, 0x01],
        };

        let result = handle_request(&test_logger(), &Config::default(), &request);
        assert!(result.is_err(), "should error on garbage input");
    }

    #[test]
    fn test_handle_request_current_user() {
        let current_user = User::from_uid(nix::unistd::geteuid()).unwrap().unwrap();

        let request = protocol::Request {
            ty: protocol::RequestType::GETPWBYNAME,
            key: &CString::new(current_user.name.clone())
                .unwrap()
                .into_bytes_with_nul(),
        };

        let expected = serialize_user(Some(current_user))
            .expect("send_user should serialize current user data");
        let output = handle_request(&test_logger(), &Config::default(), &request)
            .expect("should handle request with no error");
        assert_eq!(expected, output);
    }

    #[test]
    fn test_handle_request_getai() {
        let request = protocol::Request {
            ty: protocol::RequestType::GETAI,
            key: &CString::new("localhost".to_string())
                .unwrap()
                .into_bytes_with_nul(),
        };

        // The getaddrinfo call can actually return different ordering, or in the case of a
        // IPv4-only host, only return an IPv4 response.
        // Be happy with any of these permutations.
        let gen_ai_resp = |addrs| protocol::AiResponse {
            addrs,
            canon_name: "localhost".to_string(),
        };
        let ai_resp_1 = gen_ai_resp(vec![
            IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        ]);
        let ai_resp_2 = gen_ai_resp(vec![
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
        ]);
        let ai_resp_3 = gen_ai_resp(vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))]);
        let expected_1: Vec<u8> = serialize_address_info(ai_resp_1)
            .expect("serialize_address_info should serialize correctly");
        let expected_2: Vec<u8> = serialize_address_info(ai_resp_2)
            .expect("serialize_address_info should serialize correctly");
        let expected_3: Vec<u8> = serialize_address_info(ai_resp_3)
            .expect("serialize_address_info should serialize correctly");

        let output = handle_request(&test_logger(), &Config::default(), &request)
            .expect("should handle request with no error");

        assert!(
            expected_1 == output || expected_2 == output || expected_3 == output,
            "\nExpecting \n{:?}\nTo be equal to\n{:?}\nor\n{:?}\nor\n{:?}\n",
            output,
            expected_1,
            expected_2,
            expected_3
        );
    }

    #[test]
    fn test_handle_gethostbyaddr() {
        let request = protocol::Request {
            ty: protocol::RequestType::GETHOSTBYADDR,
            key: &[127, 0, 0, 1],
        };

        let expected = serialize_hostent(Hostent {
            addr_list: vec![IpAddr::from(Ipv4Addr::new(127, 0, 0, 1))],
            name: CString::new(b"localhost".to_vec()).unwrap(),
            addr_type: AF_INET,
            aliases: Vec::new(),
            herrno: 0,
        })
        .expect("must serialize");

        let output = handle_request(&test_logger(), &Config::default(), &request)
            .expect("should handle request with no error");

        assert_eq!(expected, output)
    }

    #[test]
    fn test_handle_gethostbyaddr_invalid_len() {
        let request = protocol::Request {
            ty: protocol::RequestType::GETHOSTBYADDR,
            key: &[127, 0, 0],
        };

        let result = handle_request(&test_logger(), &Config::default(), &request);

        assert!(result.is_err(), "should error on invalid length");
    }

    #[test]
    // Fails on CI: depending on the host setup, we might get
    // different or less aliases for localhost.
    #[ignore]
    fn test_handle_gethostbyaddrv6() {
        let request = protocol::Request {
            ty: protocol::RequestType::GETHOSTBYADDRv6,
            key: &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        };

        let expected = serialize_hostent(Hostent {
            addr_list: vec![IpAddr::from(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))],
            name: CString::new(b"localhost".to_vec()).unwrap(),
            addr_type: AF_INET6,
            aliases: Vec::new(),
            herrno: 0,
        })
        .expect("must serialize");

        let output = handle_request(&test_logger(), &Config::default(), &request)
            .expect("should handle request with no error");

        assert_eq!(expected, output)
    }

    #[test]
    fn test_handle_gethostbyaddrv6_invalid_len() {
        let request = protocol::Request {
            ty: protocol::RequestType::GETHOSTBYADDRv6,
            key: &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        };

        let result = handle_request(&test_logger(), &Config::default(), &request);

        assert!(result.is_err(), "should error on invalid length");
    }

    #[test]
    fn test_hostent_serialization() {
        let hostent = serialize_hostent(Hostent {
            name: CString::new(b"trantor.alternativebit.fr".to_vec()).unwrap(),
            aliases: vec![CString::new(b"trantor".to_vec()).unwrap()],
            addr_type: AF_INET6,
            addr_list: vec![IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))],
            herrno: 0,
        })
        .expect("should serialize");

        // Captured through a mismatched sockburp run
        let expected_bytes: Vec<u8> = vec![
            0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x1a, 0x00, 0x00, 0x00, 0x01, 0x00,
            0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x74, 0x72, 0x61, 0x6e, 0x74, 0x6f, 0x72, 0x2e, 0x61, 0x6c,
            0x74, 0x65, 0x72, 0x6e, 0x61, 0x74, 0x69, 0x76, 0x65, 0x62, 0x69, 0x74, 0x2e, 0x66,
            0x72, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x74, 0x72, 0x61, 0x6e, 0x74, 0x6f,
            0x72, 0x00,
        ];
        assert_eq!(hostent, expected_bytes)
    }

    // Test data for the below harvested using socat between nscd and docker container

    #[test]
    fn test_handle_getservbyport_port() {
        // getent service 23 (telnet)
        let request = protocol::Request {
            ty: protocol::RequestType::GETSERVBYPORT,
            key: &[0x35, 0x38, 0x38, 0x38, 0x2f, 0x00],
        };
        let expected_bytes: Vec<u8> = vec![
            0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x04, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00, 0x74, 0x65, 0x6c, 0x6e,
            0x65, 0x74, 0x00, 0x74, 0x63, 0x70, 0x00,
        ];
        let result = handle_request(&test_logger(), &Config::default(), &request)
            .expect("should handle request with no error");

        assert_eq!(result, expected_bytes);
    }

    #[test]
    fn test_handle_getservbyport_port_proto() {
        // getent services 49/udp (tacacs)
        let request = protocol::Request {
            ty: protocol::RequestType::GETSERVBYPORT,
            key: &[0x31, 0x32, 0x35, 0x34, 0x34, 0x2f, 0x75, 0x64, 0x70, 0x00],
        };
        let expected_bytes: Vec<u8> = vec![
            0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x04, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x31, 0x00, 0x00, 0x74, 0x61, 0x63, 0x61,
            0x63, 0x73, 0x00, 0x75, 0x64, 0x70, 0x00,
        ];
        let result = handle_request(&test_logger(), &Config::default(), &request)
            .expect("should handle request with no error");
        assert_eq!(result, expected_bytes);
    }

    #[test]
    fn test_handle_getservbyname_name() {
        // getent service domain
        let request = protocol::Request {
            ty: protocol::RequestType::GETSERVBYNAME,
            key: &[
                0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x2f, 0x75, 0x64, 0x70, 0x00,
            ],
        };
        let expected_bytes: Vec<u8> = vec![
            0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x04, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x35, 0x00, 0x00, 0x64, 0x6f, 0x6d, 0x61,
            0x69, 0x6e, 0x00, 0x75, 0x64, 0x70, 0x00,
        ];
        let result = handle_request(&test_logger(), &Config::default(), &request)
            .expect("should handle request with no error");

        assert_eq!(result, expected_bytes);
    }
    #[test]
    fn test_handle_getservbyname_name_proto() {
        // getent service domain/udp
        let request = protocol::Request {
            ty: protocol::RequestType::GETSERVBYNAME,
            key: &[0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x2f, 0x00],
        };
        let expected_bytes: Vec<u8> = vec![
            0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x04, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x35, 0x00, 0x00, 0x64, 0x6f, 0x6d, 0x61,
            0x69, 0x6e, 0x00, 0x74, 0x63, 0x70, 0x00,
        ];
        let result = handle_request(&test_logger(), &Config::default(), &request)
            .expect("should handle request with no error");

        assert_eq!(result, expected_bytes);
    }

    #[test]
    fn test_handle_getservbyport_port_proto_aliases() {
        // getent service 113/tcp
        // Returns 3 aliases
        // auth                  113/tcp authentication tap ident
        let request = protocol::Request {
            ty: protocol::RequestType::GETSERVBYPORT,
            key: &[0x32, 0x38, 0x39, 0x32, 0x38, 0x2f, 0x74, 0x63, 0x70, 0x00],
        };
        let expected_bytes: Vec<u8> = vec![
            0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x04, 0x00,
            0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x71, 0x00, 0x00, 0x61, 0x75, 0x74, 0x68,
            0x00, 0x74, 0x63, 0x70, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x06,
            0x00, 0x00, 0x00, 0x61, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74,
            0x69, 0x6f, 0x6e, 0x00, 0x74, 0x61, 0x70, 0x00, 0x69, 0x64, 0x65, 0x6e, 0x74, 0x00,
        ];
        let result = handle_request(&test_logger(), &Config::default(), &request)
            .expect("should handle request with no error");

        assert_eq!(result, expected_bytes);
    }

    // unit tests of netgroup are a bit harder without /etc/netgroup data

    #[test]
    fn test_netgroup_serialization() {
        // validate netgroup response serialization
        let netgroupents = serialize_netgroup(vec![
            Netgroup {
                host: Some(CString::new(b"host1".to_vec()).unwrap()),
                user: Some(CString::new(b"user1".to_vec()).unwrap()),
                domain: Some(CString::new(b"domain1".to_vec()).unwrap()),
            },
            Netgroup {
                host: Some(CString::new(b"host2".to_vec()).unwrap()),
                user: Some(CString::new(b"user2".to_vec()).unwrap()),
                domain: Some(CString::new(b"domain2".to_vec()).unwrap()),
            },
        ])
        .expect("should serialize");

        let expected_bytes: Vec<u8> = vec![
            0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x28, 0x00,
            0x00, 0x00, 0x68, 0x6f, 0x73, 0x74, 0x31, 0x00, 0x75, 0x73, 0x65, 0x72, 0x31, 0x00,
            0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x31, 0x00, 0x68, 0x6f, 0x73, 0x74, 0x32, 0x00,
            0x75, 0x73, 0x65, 0x72, 0x32, 0x00, 0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x32, 0x00,
        ];
        assert_eq!(netgroupents, expected_bytes)
    }

    #[test]
    fn test_handle_in_netgr_request() {
        // innetgr is the only request with multiple values delimited by NUL
        // ensure from_bytes works
        let in_netgroup_req = InNetGroup::from_bytes(&[
            0x6e, 0x65, 0x74, 0x67, 0x72, 0x6f, 0x75, 0x70, 0x00, 0x01, 0x68, 0x6f, 0x73, 0x74,
            0x31, 0x00, 0x01, 0x75, 0x73, 0x65, 0x72, 0x31, 0x00, 0x01, 0x64, 0x6f, 0x6d, 0x61,
            0x69, 0x6e, 0x31, 0x00,
        ])
        .expect("should serialize");
        let expected = InNetGroup {
            netgroup: String::from("netgroup"),
            host: Some(String::from("host1")),
            user: Some(String::from("user1")),
            domain: Some(String::from("domain1")),
        };

        assert_eq!(in_netgroup_req, expected);
    }

    #[test]
    fn test_innetgroup_serialization_in_group() {
        // validate innetgr serialization
        let in_netgroup = serialize_innetgr(true).expect("should serialize");
        let expected_bytes: Vec<u8> = vec![
            0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        ];
        assert_eq!(in_netgroup, expected_bytes)
    }

    #[test]
    fn test_innetgroup_serialization_not_in_group() {
        // validate innetgr serialization
        let in_netgroup = serialize_innetgr(false).expect("should serialize");
        let expected_bytes: Vec<u8> = vec![];
        assert_eq!(in_netgroup, expected_bytes)
    }
}
