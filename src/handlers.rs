/*
 * Copyright 2020 Two Sigma Open Source, LLC
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
use nix::unistd::{Gid, Group, Uid, User};
use slog::{debug, Logger};

use super::protocol;
use super::protocol::RequestType;

/// Handle a request by performing the appropriate lookup and sending the
/// serialized response back to the client.
///
/// # Arguments
///
/// * `log` - A `slog` Logger.
/// * `request` - The request to handle.
/// * `send_slice` - A callback that will be used to send bytes back to the client, if
///   there is a response to send.
pub fn handle_request<F>(log: &Logger, request: &protocol::Request, send_slice: F) -> Result<()>
where
    F: FnMut(&[u8]) -> Result<()>,
{
    debug!(log, "handling request"; "request" => ?request);
    match request.ty {
        RequestType::GETPWBYUID => {
            let key = CStr::from_bytes_with_nul(request.key)?;
            let uid = atoi::<u32>(key.to_bytes()).context("invalid uid string")?;
            let user = User::from_uid(Uid::from_raw(uid))?;
            send_user(log, user, send_slice)
        }
        RequestType::GETPWBYNAME => {
            let key = CStr::from_bytes_with_nul(request.key)?;
            let user = User::from_name(key.to_str()?)?;
            send_user(log, user, send_slice)
        }
        RequestType::GETGRBYGID => {
            let key = CStr::from_bytes_with_nul(request.key)?;
            let gid = atoi::<u32>(key.to_bytes()).context("invalid gid string")?;
            let group = Group::from_gid(Gid::from_raw(gid))?;
            send_group(log, group, send_slice)
        }
        RequestType::GETGRBYNAME => {
            let key = CStr::from_bytes_with_nul(request.key)?;
            let group = Group::from_name(key.to_str()?)?;
            send_group(log, group, send_slice)
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
        | RequestType::LASTREQ
        | RequestType::INITGROUPS => Ok(()),
    }
}

/// Send a user (passwd entry) back to the client, or a response indicating the
/// lookup found no such user.
fn send_user<F>(log: &Logger, user: Option<User>, mut send_slice: F) -> Result<()>
where
    F: FnMut(&[u8]) -> Result<()>,
{
    debug!(log, "got user"; "user" => ?user);
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
        send_slice(header.as_slice())?;
        send_slice(name_bytes)?;
        send_slice(passwd_bytes)?;
        send_slice(gecos_bytes)?;
        send_slice(dir_bytes)?;
        send_slice(shell_bytes)?;
    } else {
        let header = protocol::PwResponseHeader::default();
        send_slice(header.as_slice())?;
    }
    Ok(())
}

/// Send a group (group entry) back to the client, or a response indicating the
/// lookup found no such group.
fn send_group<F>(log: &Logger, group: Option<Group>, mut send_slice: F) -> Result<()>
where
    F: FnMut(&[u8]) -> Result<()>,
{
    debug!(log, "got group"; "group" => ?group);
    if let Some(data) = group {
        let name = CString::new(data.name)?;
        let name_bytes = name.to_bytes_with_nul();
        let passwd_bytes = data.passwd.to_bytes_with_nul();
        let members_bytes: Vec<Vec<u8>> = data
            .mem
            .iter()
            .map(|member| CString::new(member.as_bytes()).map(|cs| cs.into_bytes_with_nul()))
            .collect::<Result<Vec<Vec<u8>>, _>>()?;

        let header = protocol::GrResponseHeader {
            version: protocol::VERSION,
            found: 1,
            gr_name_len: name_bytes.len().try_into()?,
            gr_passwd_len: passwd_bytes.len().try_into()?,
            gr_gid: data.gid.as_raw(),
            gr_mem_cnt: data.mem.len().try_into()?,
        };
        send_slice(header.as_slice())?;
        for member_bytes in members_bytes.iter() {
            send_slice(&i32::to_ne_bytes(member_bytes.len().try_into()?))?;
        }
        send_slice(name_bytes)?;
        send_slice(passwd_bytes)?;
        for member_bytes in members_bytes.iter() {
            send_slice(member_bytes)?;
        }
    } else {
        let header = protocol::GrResponseHeader::default();
        send_slice(header.as_slice())?;
    }
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;

    fn send_to(v: &mut Vec<u8>) -> impl FnMut(&[u8]) -> Result<()> + '_ {
        move |bs| {
            v.extend_from_slice(bs);
            Ok(())
        }
    }

    fn test_logger() -> slog::Logger {
        Logger::root(slog::Discard, slog::o!())
    }

    #[test]
    fn test_handle_request_empty_key() {
        let mut output = vec![];
        let request = protocol::Request {
            ty: protocol::RequestType::GETPWBYNAME,
            key: &[],
        };

        assert!(
            handle_request(&test_logger(), &request, send_to(&mut output)).is_err(),
            "should error on empty input"
        );
        assert!(output.is_empty());
    }

    #[test]
    fn test_handle_request_nul_data() {
        let mut output = vec![];
        let request = protocol::Request {
            ty: protocol::RequestType::GETPWBYNAME,
            key: &[0x7F, 0x0, 0x0, 0x01],
        };

        assert!(
            handle_request(&test_logger(), &request, send_to(&mut output)).is_err(),
            "should error on garbage input"
        );
        assert!(output.is_empty());
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

        let mut expected = vec![];
        send_user(&test_logger(), Some(current_user), send_to(&mut expected))
            .expect("send_user should serialize current user data");

        let mut output: Vec<u8> = vec![];
        handle_request(&test_logger(), &request, send_to(&mut output))
            .expect("should handle request with no error");
        assert_eq!(expected, output);
    }
}
