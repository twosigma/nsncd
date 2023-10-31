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
use std::mem::size_of;

use crate::ffi::{gethostbyaddr_r, gethostbyname2_r, Hostent, LibcIp};
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
                    let addrs: Vec<IpAddr> = ai_resp_iter
                            .map(|e| e.sockaddr.ip())
                            .collect();

                    AiResponse {
                        canon_name,
                        addrs,
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
            let hostent = match gethostbyaddr_r(LibcIp::V4(address_bytes)) {
                Ok(hostent) => hostent,
                Err(e) =>
                // We shouldn't end up in that branch. Something
                // got very very wrong on the glibc client side if
                // we do. It's okay to bail, there's nothing much
                // we can do.
                {
                    bail!("unexpected gethostbyaddr error: {}", e)
                }
            };
            hostent.serialize()
        }
        RequestType::GETHOSTBYADDRv6 => {
            let key = request.key;

            if key.len() != 16 {
                bail!("Invalid key len: {}, expected 16", key.len());
            }
            let address_bytes: [u8; 16] = key.try_into()?;
            let hostent = match gethostbyaddr_r(LibcIp::V6(address_bytes)) {
                Ok(hostent) => hostent,
                Err(e) =>
                // We shouldn't end up in that branch. Something
                // got very very wrong on the glibc client side if
                // we do. It's okay to bail, there's nothing much
                // we can do.
                {
                    bail!("unexpected gethostbyaddrv6 error: {}", e)
                }
            };
            hostent.serialize()
        }

        RequestType::GETHOSTBYNAME => {
            let hostname = CStr::from_bytes_with_nul(request.key)?.to_str()?;
            let hostent = match gethostbyname2_r(hostname.to_string(), nix::libc::AF_INET) {
                Ok(hostent) => hostent,
                Err(e) =>
                // We shouldn't end up in that branch. Something
                // got very very wrong on the glibc client side if
                // we do. It's okay to bail, there's nothing much
                // we can do.
                {
                    bail!("unexpected gethostbyname error: {:?}", e)
                }
            };
            hostent.serialize()
        }

        RequestType::GETHOSTBYNAMEv6 => {
            let hostname = CStr::from_bytes_with_nul(request.key)?.to_str()?;
            let hostent = match gethostbyname2_r(hostname.to_string(), nix::libc::AF_INET6) {
                Ok(hostent) => hostent,
                Err(e) =>
                // We shouldn't end up in that branch. Something
                // got very very wrong on the glibc client side if
                // we do. It's okay to bail, there's nothing much
                // we can do.
                {
                    bail!("unexpected gethostbynamev6 error: {:?}", e)
                }
            };
            hostent.serialize()
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

impl Hostent {
    fn serialize(&self) -> Result<Vec<u8>> {
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

        for address in self.addr_list.iter() {
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

        for alias in self.aliases.iter() {
            let alias_bytes = CString::new(alias.clone())?.into_bytes_with_nul();
            let size_in_bytes = alias_bytes.len() as i32;
            buf_aliases_size.extend_from_slice(&size_in_bytes.to_ne_bytes());
            buf_aliases.extend_from_slice(alias_bytes.as_slice());
        }

        // this can only ever express one address family
        if num_v4 != 0 && num_v6 != 0 {
            bail!("unable to serialize mixed AF")
        }

        let num_addrs = num_v4 + num_v6;
        let has_addrs = num_addrs > 0;

        let hostname_c_string_bytes = CString::new(self.name.clone())?.into_bytes_with_nul();
        let hostname_c_string_len = if has_addrs {
            hostname_c_string_bytes.len()
        } else {
            0
        };

        let buf = if num_addrs > 0 {

            let header = protocol::HstResponseHeader {
                version: protocol::VERSION,
                found: 1,
                h_name_len: hostname_c_string_len as i32,
                h_aliases_cnt: self.aliases.len() as i32,
                h_addrtype: if num_v4 != 0 {
                    nix::sys::socket::AddressFamily::Inet as i32
                } else {
                    nix::sys::socket::AddressFamily::Inet6 as i32
                },
                h_length: if num_v4 != 0 {
                    4
                } else {
                    16
                },
                h_addr_list_cnt: num_addrs,
                error: self.herrno,
            };

            let total_len = std::mem::size_of::<protocol::HstResponseHeader>()
                + hostname_c_string_len
                + buf_addrs.len()
                + buf_aliases.len()
                + buf_aliases_size.len();

            let mut buf = Vec::with_capacity(total_len);

            // add header
            buf.extend_from_slice(header.as_slice());

            // add hostname
            buf.extend_from_slice(&hostname_c_string_bytes);

            // add aliases sizes
            buf.extend_from_slice(buf_aliases_size.as_slice());

            // add serialized addresses from buf_addrs
            buf.extend_from_slice(buf_addrs.as_slice());

            // add aliases
            buf.extend_from_slice(buf_aliases.as_slice());

            debug_assert_eq!(buf.len(), total_len);

            buf
        } else {
            let error_header = protocol::HstResponseHeader {
                version: protocol::VERSION,
                found: 0,
                h_name_len: 0,
                h_aliases_cnt: 0,
                h_addrtype: -1,
                h_length: -1,
                h_addr_list_cnt: 0,
                error: self.herrno,
            };
            Vec::from(error_header.as_slice())
        };

        Ok(buf)
    }
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
/// 6. error: int32. Error code. Always 0 in the current nscd
///           implementation.
/// 7. addrs: \[BE-encoded IPv4/IPv6\]. We sequentially write the
///    IPv4 and IPv6 bytes using a big endian encoding. There's no
///    padding, an IPv4 will be 4 bytes wide, an IPv6 16 bytes wide.
/// 8. addr_family: \[uint8\]. This array mirrors the addrs array. Each
///    addr element will be mirrored in this array, except we'll write
///    the associated IP addr family number. AF_INET for an IPv4,
///    AF_INET6 for a v6.
/// 9. canon_name: Canonical name of the host. Null-terminated string.
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

#[cfg(test)]
mod test {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use nix::libc::{AF_INET, AF_INET6};

    use super::super::config::Config;
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

        let expected = (Hostent {
            addr_list: vec![IpAddr::from(Ipv4Addr::new(127, 0, 0, 1))],
            name: "localhost".to_string(),
            addr_type: AF_INET,
            aliases: Vec::new(),
            herrno: 0,
        })
        .serialize()
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

        let expected = (Hostent {
            addr_list: vec![IpAddr::from(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))],
            name: "localhost".to_string(),
            addr_type: AF_INET6,
            aliases: Vec::new(),
            herrno: 0,
        })
        .serialize()
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
        let hostent = Hostent {
            name: String::from("trantor.alternativebit.fr"),
            aliases: vec![String::from("trantor")],
            addr_type: AF_INET6,
            addr_list: vec![IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))],
            herrno: 0,
        }
        .serialize()
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
}
