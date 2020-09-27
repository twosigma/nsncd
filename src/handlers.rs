use std::ffi::CString;
use std::mem::size_of;
use std::os::unix::ffi::OsStrExt;

use anyhow::{Context, Result};
use atoi::atoi;
use nix::unistd::{Gid, Group, Uid, User};
use slog::Logger;

use super::protocol;

pub fn handle_request<SendSlice>(
    log: Logger,
    request: &protocol::Request,
    send: SendSlice,
) -> Result<()>
where
    SendSlice: FnMut(&[u8]) -> Result<()>,
{
    debug!(log, "handling request"; "request" => ?request);
    match request.type_ {
        protocol::RequestType::GETPWBYUID => {
            let uid = atoi::<u32>(request.key.to_bytes()).context("invalid uid string")?;
            let user = User::from_uid(Uid::from_raw(uid))?;
            send_user(log, user, send)
        }
        protocol::RequestType::GETPWBYNAME => {
            let user = User::from_name(request.key.to_str()?)?;
            send_user(log, user, send)
        }
        protocol::RequestType::GETGRBYGID => {
            let gid = atoi::<u32>(request.key.to_bytes()).context("invalid gid string")?;
            let group = Group::from_gid(Gid::from_raw(gid))?;
            send_group(log, group, send)
        }
        protocol::RequestType::GETGRBYNAME => {
            let group = Group::from_name(request.key.to_str()?)?;
            send_group(log, group, send)
        }
        _ => Ok(()),
    }
}

fn send_user<SendSlice>(log: Logger, user: Option<User>, mut send: SendSlice) -> Result<()>
where
    SendSlice: FnMut(&[u8]) -> Result<()>,
{
    #[repr(C)]
    union Union {
        data: protocol::PwResponseHeader,
        bytes: [u8; size_of::<protocol::PwResponseHeader>()],
    };

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

        let u = Union {
            data: protocol::PwResponseHeader {
                version: protocol::VERSION,
                found: 1,
                pw_name_len: name_bytes.len() as i32,
                pw_passwd_len: passwd_bytes.len() as i32,
                pw_uid: data.uid.as_raw(),
                pw_gid: data.gid.as_raw(),
                pw_gecos_len: gecos_bytes.len() as i32,
                pw_dir_len: dir_bytes.len() as i32,
                pw_shell_len: shell_bytes.len() as i32,
            },
        };
        let header_bytes = unsafe { u.bytes };
        send(header_bytes.as_slice())?;
        send(name_bytes)?;
        send(passwd_bytes)?;
        send(gecos_bytes)?;
        send(dir_bytes)?;
        send(shell_bytes)?;
    } else {
        let u = Union {
            data: protocol::PwResponseHeader::default(),
        };
        let header_bytes = unsafe { u.bytes };
        send(header_bytes.as_slice())?;
    }
    Ok(())
}

fn send_group<SendSlice>(log: Logger, group: Option<Group>, mut send: SendSlice) -> Result<()>
where
    SendSlice: FnMut(&[u8]) -> Result<()>,
{
    #[repr(C)]
    union Union {
        data: protocol::GrResponseHeader,
        bytes: [u8; size_of::<protocol::GrResponseHeader>()],
    };

    debug!(log, "got group"; "group" => ?group);
    if let Some(data) = group {
        let name = CString::new(data.name)?;
        let name_bytes = name.to_bytes_with_nul();
        let passwd = CString::new("x")?; // The nix crate doesn't give us the password
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

        let u = Union {
            data: protocol::GrResponseHeader {
                version: protocol::VERSION,
                found: 1,
                gr_name_len: name_bytes.len() as i32,
                gr_passwd_len: passwd_bytes.len() as i32,
                gr_gid: data.gid.as_raw(),
                gr_mem_cnt: data.mem.len() as i32,
            },
        };
        let header_bytes = unsafe { u.bytes };
        send(header_bytes.as_slice())?;
        for member_bytes in members_bytes.iter() {
            send(i32::to_ne_bytes(member_bytes.len() as i32).as_slice())?;
        }
        send(name_bytes)?;
        send(passwd_bytes)?;
        for member_bytes in members_bytes.iter() {
            send(member_bytes)?;
        }
    } else {
        let u = Union {
            data: protocol::GrResponseHeader::default(),
        };
        let header_bytes = unsafe { u.bytes };
        send(header_bytes.as_slice())?;
    }
    Ok(())
}
