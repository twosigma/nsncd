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

use std::convert::TryInto;
use std::ffi::{CStr, CString};
use std::os::unix::ffi::OsStrExt;

use anyhow::{Context, Result};
use atoi::atoi;
use nix::unistd::{getgrouplist, Gid, Group, Uid, User};
use slog::{debug, error, Logger};

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
        RequestType::GETHOSTBYADDR
        | RequestType::GETHOSTBYADDRv6
        | RequestType::GETHOSTBYNAME
        | RequestType::GETHOSTBYNAMEv6
        | RequestType::SHUTDOWN
        | RequestType::GETSTAT
        | RequestType::INVALIDATE
        | RequestType::GETFDPW
        | RequestType::GETFDGR
        | RequestType::GETFDHST
        | RequestType::GETAI
        | RequestType::GETSERVBYNAME
        | RequestType::GETSERVBYPORT
        | RequestType::GETFDSERV
        | RequestType::GETFDNETGR
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

#[cfg(test)]
mod test {
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
}
