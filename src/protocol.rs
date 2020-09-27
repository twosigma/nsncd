use std::convert::TryInto;
use std::ffi::CStr;

use anyhow::{ensure, Context, Result};
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;

use nix::libc::{c_int, gid_t, uid_t};

pub const VERSION: i32 = 2;

/* Available services.  */
#[derive(Debug, FromPrimitive)]
pub enum RequestType {
    GETPWBYNAME,
    GETPWBYUID,
    GETGRBYNAME,
    GETGRBYGID,
    GETHOSTBYNAME,
    GETHOSTBYNAMEv6,
    GETHOSTBYADDR,
    GETHOSTBYADDRv6,
    SHUTDOWN,   /* Shut the server down.  */
    GETSTAT,    /* Get the server statistic.  */
    INVALIDATE, /* Invalidate one special cache.  */
    GETFDPW,
    GETFDGR,
    GETFDHST,
    GETAI,
    INITGROUPS,
    GETSERVBYNAME,
    GETSERVBYPORT,
    GETFDSERV,
    GETNETGRENT,
    INNETGR,
    GETFDNETGR,
    LASTREQ,
}

#[derive(Debug)]
pub struct Request<'a> {
    pub type_: RequestType,
    pub key: &'a CStr,
}

impl<'a> Request<'a> {
    pub fn parse(buf: &'a [u8]) -> Result<Request<'a>> {
        ensure!(buf.len() >= 12, "request body too small");

        let version = buf[0..4].try_into().map(i32::from_ne_bytes)?;
        ensure!(version == VERSION, "wrong protocol version {}", version);

        let type_val = buf[4..8].try_into().map(i32::from_ne_bytes)?;
        let type_ = FromPrimitive::from_i32(type_val)
            .with_context(|| format!("invalid enum value {}", type_val))?;

        let key_len = buf[8..12].try_into().map(i32::from_ne_bytes)?;
        let key_end = 12 + key_len as usize;
        ensure!(buf.len() >= key_end, "request body too small");

        let key = CStr::from_bytes_with_nul(&buf[12..key_end])?;
        Ok(Request { type_, key })
    }
}

/* Structure sent in reply to password query.  Note that this struct is
sent also if the service is disabled or there is no record found.  */
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct PwResponseHeader {
    pub version: c_int,
    pub found: c_int,
    pub pw_name_len: c_int,
    pub pw_passwd_len: c_int,
    pub pw_uid: uid_t,
    pub pw_gid: gid_t,
    pub pw_gecos_len: c_int,
    pub pw_dir_len: c_int,
    pub pw_shell_len: c_int,
}

/* Structure sent in reply to group query.  Note that this struct is
sent also if the service is disabled or there is no record found.  */
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct GrResponseHeader {
    pub version: c_int,
    pub found: c_int,
    pub gr_name_len: c_int,
    pub gr_passwd_len: c_int,
    pub gr_gid: gid_t,
    pub gr_mem_cnt: c_int,
}
