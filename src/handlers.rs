/*
 * Copyright 2020-2022 Two Sigma Open Source, LLC
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

use std::collections::HashSet;
use std::convert::TryInto;
use std::ffi::{CStr, CString};
use std::net::{IpAddr, SocketAddr};
use std::os::unix::ffi::OsStrExt;

use anyhow::{bail, Context, Result};
use atoi::atoi;
use dns_lookup::{getaddrinfo, getnameinfo, AddrInfoHints};
use nix::libc::{AF_INET6, NI_NUMERICSERV, SOCK_STREAM};
use nix::sys::socket::AddressFamily;
use nix::unistd::{getgrouplist, Gid, Group, Uid, User};
use slog::{debug, error, Logger};
use std::mem::size_of;

use crate::protocol::{AiResponse, AiResponseHeader};

use super::config::Config;
use super::protocol;
use super::protocol::RequestType;

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
            let uid = atoi::<u32>(key.to_bytes()).context("invalid uid string")?;
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
            let gid = atoi::<u32>(key.to_bytes()).context("invalid gid string")?;
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
            let resp = dns_lookup::getaddrinfo(Some(hostname), None, None);

            let ai_resp_empty = AiResponse {
                canon_name: hostname.to_string(),
                addrs: vec![],
            };

            let ai_resp: AiResponse = match resp {
                Ok(ai_resp_iter) => {
                    let addrs: HashSet<IpAddr> = ai_resp_iter
                        .filter_map(|e| e.ok())
                        .map(|e| e.sockaddr.ip())
                        .collect();
                    AiResponse {
                        canon_name: hostname.to_string(),
                        addrs: addrs.iter().copied().collect::<Vec<IpAddr>>(),
                    }
                }
                Err(_) => ai_resp_empty,
            };

            serialize_address_info(&ai_resp)
        }

        // GETHOSTBYADDR and GETHOSTBYADDRv6 implement reverse lookup
        // The key contains the address to look for.
        RequestType::GETHOSTBYADDR => {
            let key = request.key;

            if key.len() != 4 {
                bail!("Invalid key len: {}, expected 4", key.len());
            }
            let address_bytes: [u8; 4] = key.try_into()?;
            let address = IpAddr::from(address_bytes);

            let sock = SocketAddr::new(address, 0);
            let host = match getnameinfo(&sock, NI_NUMERICSERV) {
                Ok((hostname, _service)) => Ok(Some(Host {
                    addresses: vec![address],
                    hostname,
                })),
                Err(e) => match e.kind() {
                    dns_lookup::LookupErrorKind::NoName => Ok(None),
                    _ => bail!("error during lookup: {:?}", e),
                },
            };
            Ok(serialize_host(log, host))
        }
        RequestType::GETHOSTBYADDRv6 => {
            let key = request.key;

            if key.len() != 16 {
                bail!("Invalid key len: {}, expected 16", key.len());
            }
            let address_bytes: [u8; 16] = key.try_into()?;
            let address = IpAddr::from(address_bytes);

            let sock = SocketAddr::new(address, 0);
            let host = match getnameinfo(&sock, NI_NUMERICSERV) {
                Ok((hostname, _service)) => Ok(Some(Host {
                    addresses: vec![address],
                    hostname,
                })),
                Err(e) => match e.kind() {
                    dns_lookup::LookupErrorKind::NoName => Ok(None),
                    _ => bail!("error during lookup: {:?}", e),
                },
            };
            Ok(serialize_host(log, host))
        }

        RequestType::GETHOSTBYNAME => {
            let hostname = CStr::from_bytes_with_nul(request.key)?.to_str()?;
            let hints = AddrInfoHints {
                socktype: SOCK_STREAM,
                ..AddrInfoHints::default()
            };

            let host = match getaddrinfo(Some(hostname), None, Some(hints)).map(|addrs| {
                addrs
                    .filter_map(|r| r.ok())
                    .filter(|r| r.sockaddr.is_ipv4())
                    .map(|a| a.sockaddr.ip())
                    .collect::<Vec<_>>()
            }) {
                // no matches found
                Ok(addresses) if addresses.len() == 0 => Ok(None),
                Ok(addresses) => Ok(Some(Host {
                    addresses,
                    hostname: hostname.to_string(),
                })),
                Err(e) => match e.kind() {
                    dns_lookup::LookupErrorKind::NoName => Ok(None),
                    _ => bail!("error during lookup: {:?}", e),
                },
            };
            Ok(serialize_host(log, host))
        }

        RequestType::GETHOSTBYNAMEv6 => {
            let hostname = CStr::from_bytes_with_nul(request.key)?.to_str()?;

            let hints = AddrInfoHints {
                socktype: SOCK_STREAM,
                address: AF_INET6, // ai_family
                ..AddrInfoHints::default()
            };

            let host = match getaddrinfo(Some(hostname), None, Some(hints)) {
                Ok(addrs) => {
                    let addresses: std::io::Result<Vec<_>> = addrs
                        .filter(|x| match x {
                            Err(_) => false,
                            Ok(addr) => addr.sockaddr.is_ipv6(),
                        })
                        .map(|r| r.map(|a| a.sockaddr.ip()))
                        .collect();
                    Ok(Some(Host {
                        addresses: addresses?,
                        hostname: hostname.to_string(),
                    }))
                }
                Err(e) => match e.kind() {
                    dns_lookup::LookupErrorKind::NoName => Ok(None),
                    _ => bail!("error during lookup: {:?}", e),
                },
            };
            Ok(serialize_host(log, host))
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
        RequestType::GETSTAT
        | RequestType::GETSERVBYNAME
        | RequestType::GETSERVBYPORT
        | RequestType::GETNETGRENT
        | RequestType::INNETGR
        | RequestType::LASTREQ => Ok(vec![]),
    }
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
        // The nix crate doesn't give us the password: https://github.com/nix-rust/nix/pull/1338
        let passwd = CString::new("x")?;
        let passwd_bytes = passwd.to_bytes_with_nul();
        let members: Vec<CString> = data
            .mem
            .iter()
            .map(|member| CString::new((*member).as_bytes()))
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
            gr_mem_cnt: data.mem.len().try_into()?,
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

pub struct Host {
    pub addresses: Vec<std::net::IpAddr>,
    // aliases is unused so far
    pub hostname: String,
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
/// 4. addrslen: int32. Total lenght of the IPv4/6 adresses we're
///    about to write.
/// 5. canonlen: int32. Total lenght of the null-terminated canonical
///    name string.
/// 6. error: int32. Error code. Always 0 in the current nscd
///           implementation.
/// 7. addrs: \[BE-encoded IPv4/IPv6\]. We sequentially write the
///    IPv4 and IPv6 bytes using a big endian encoding. There's no
///    padding, an IPv4 will be 4 bytes wide, an IPv6 16 bytes wide.
/// 8. addr_family: \[uint8\]. This array mirrors the addrs array. Each
///    addr element will be mirrored in this array, except we'll write
///    the associated IP addr family number. AF_INET for an IPv4,
///    AF_INET6 for a v6.
fn serialize_address_info(resp: &AiResponse) -> Result<Vec<u8>> {
    let mut b_families: Vec<u8> = Vec::with_capacity(2);
    let mut b_addrs: Vec<u8> = Vec::with_capacity(2);
    for addr in &resp.addrs {
        match addr {
            IpAddr::V4(ip) => {
                b_families.push(AddressFamily::Inet as u8);
                for octet in ip.octets() {
                    b_addrs.push(octet);
                }
            }
            IpAddr::V6(ip) => {
                b_families.push(AddressFamily::Inet6 as u8);
                for segment in ip.segments() {
                    for byte in u16::to_be_bytes(segment) {
                        b_addrs.push(byte);
                    }
                }
            }
        }
    }
    let addrslen = b_addrs.len();
    if addrslen > 0 {
        let canon_name = resp.canon_name.clone();
        let b_canon_name = CString::new(canon_name)?.into_bytes_with_nul();
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

/// Send a gethostby{addr,name}{,v6} entry back to the client,
/// or a response indicating the lookup failed.
fn serialize_host(log: &slog::Logger, host: Result<Option<Host>>) -> Vec<u8> {
    let result = || {
        match host {
            Ok(Some(host)) => {
                // Loop over all addresses.
                // Serialize them into a slice, which is used later in the payload.
                // Take note of the number of addresses (by AF).
                let mut num_v4 = 0;
                let mut num_v6 = 0;
                let mut buf_addrs = vec![];

                for address in host.addresses {
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

                let num_addrs = num_v4 + num_v6;

                let hostname_c_string_bytes =
                    CString::new(host.hostname.clone())?.into_bytes_with_nul();
                let hostname_c_string_len = hostname_c_string_bytes.len();

                let header = protocol::HstResponseHeader {
                    version: protocol::VERSION,
                    found: 1 as i32,
                    h_name_len: hostname_c_string_len as i32,
                    h_aliases_cnt: 0 as i32,
                    h_addrtype: if num_v4 != 0 {
                        nix::sys::socket::AddressFamily::Inet as i32
                    } else {
                        nix::sys::socket::AddressFamily::Inet6 as i32
                    },
                    h_length: if num_v4 != 0 { 4 as i32 } else { 16 as i32 },
                    h_addr_list_cnt: num_addrs as i32,
                    error: 0,
                };

                let total_len = 4 * 8 + hostname_c_string_len as i32 + buf_addrs.len() as i32;
                let mut buf = Vec::with_capacity(total_len as usize);

                // add header
                buf.extend_from_slice(header.as_slice());

                // add hostname
                buf.extend_from_slice(&hostname_c_string_bytes);

                // add serialized addresses from buf_addrs
                buf.extend_from_slice(buf_addrs.as_slice());

                debug_assert_eq!(buf.len() as i32, total_len);

                Ok(buf)
            }
            Ok(None) => {
                let header = protocol::HstResponseHeader {
                    version: protocol::VERSION,
                    found: 0,
                    h_name_len: 0,
                    h_aliases_cnt: 0,
                    h_addrtype: -1 as i32,
                    h_length: -1 as i32,
                    h_addr_list_cnt: 0,
                    error: protocol::H_ERRNO_HOST_NOT_FOUND as i32,
                };

                let mut buf = Vec::with_capacity(4 * 8);
                buf.extend_from_slice(header.as_slice());
                Ok(buf)
            }
            Err(e) => {
                // pass along error
                Err(e)
            }
        }
    };

    match result() {
        Ok(res) => res,
        Err(e) => {
            error!(log, "parsing request"; "err" => %e);
            let header = protocol::HstResponseHeader {
                version: protocol::VERSION,
                found: 0,
                h_name_len: 0,
                h_aliases_cnt: 0,
                h_addrtype: -1 as i32,
                h_length: -1 as i32,
                h_addr_list_cnt: protocol::H_ERRNO_NETDB_INTERNAL as i32,
                error: 0,
            };

            let mut buf = Vec::with_capacity(4 * 8);
            buf.extend_from_slice(header.as_slice());
            buf
        }
    }
}

#[cfg(test)]
mod test {
    use super::super::config::Config;
    use std::net::{Ipv4Addr, Ipv6Addr};

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
        let expected_1: Vec<u8> = serialize_address_info(&ai_resp_1)
            .expect("serialize_address_info should serialize correctly");
        let expected_2: Vec<u8> = serialize_address_info(&ai_resp_2)
            .expect("serialize_address_info should serialize correctly");
        let expected_3: Vec<u8> = serialize_address_info(&ai_resp_3)
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

        let expected = serialize_host(
            &test_logger(),
            Ok(Some(Host {
                addresses: vec![IpAddr::from(Ipv4Addr::new(127, 0, 0, 1))],
                hostname: "localhost".to_string(),
            })),
        );

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
    fn test_handle_gethostbyaddrv6() {
        let request = protocol::Request {
            ty: protocol::RequestType::GETHOSTBYADDRv6,
            key: &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        };

        let expected = serialize_host(
            &test_logger(),
            Ok(Some(Host {
                addresses: vec![IpAddr::from(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))],
                hostname: "localhost".to_string(),
            })),
        );

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
}
