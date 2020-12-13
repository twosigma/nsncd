//! The nscd protocol definition (at least, the parts of it we care about).
//!
//! The response structs here only describe the format of the header of the
//! response. For each such response, if the lookup succeeded, there are
//! additional strings we need to send after the header. Those are dealt with in
//! `handlers::send_{user,group}`. For a full picture of the protocol, you will
//! need to read both.

use std::convert::TryInto;
use std::ffi::CStr;
use std::mem::size_of;

use anyhow::{ensure, Context, Result};
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;

use nix::libc::{c_int, gid_t, uid_t};

/// This is version 2 of the glibc nscd protocol. The version is passed as part
/// of each message header.
pub const VERSION: i32 = 2;

/// Available services. This enum describes all service types the nscd protocol
/// knows about, though we only implement `GETPW*` and `GETGR*`.
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
    /// Shut the server down.
    SHUTDOWN,
    /// Get the server statistic.
    GETSTAT,
    /// Invalidate one special cache.
    INVALIDATE,
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

/// An incoming request. All requests have a version, a type, and a string key.
/// This struct keeps the type and key, because that's what we need to reply to
/// it, we only handle one version and we validate, but don't retain it.
///
/// The parsed Request object is valid as long as the buffer it is parsed from
/// (that is, the key is a reference to the bytes in the buffer).
#[derive(Debug)]
pub struct Request<'a> {
    pub ty: RequestType,
    pub key: &'a CStr,
}

impl<'a> Request<'a> {
    /// Parse a Request from a buffer.
    pub fn parse(buf: &'a [u8]) -> Result<Self> {
        ensure!(buf.len() >= 12, "request body too small: {}", buf.len());

        let version = buf[0..4].try_into().map(i32::from_ne_bytes)?;
        ensure!(version == VERSION, "wrong protocol version {}", version);

        let type_val = buf[4..8].try_into().map(i32::from_ne_bytes)?;
        let ty = FromPrimitive::from_i32(type_val)
            .with_context(|| format!("invalid enum value {}", type_val))?;

        let key_len = buf[8..12].try_into().map(i32::from_ne_bytes)?;
        let key_end = (12 + key_len).try_into()?;
        ensure!(buf.len() >= key_end, "request body too small");

        let key = CStr::from_bytes_with_nul(&buf[12..key_end])?;
        Ok(Request { ty, key })
    }
}

/// Structure sent in reply to password query.  Note that this struct is
/// sent also if the service is disabled or there is no record found.
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

impl PwResponseHeader {
    /// Serialize the header to bytes.
    ///
    /// The C implementations of nscd just take the address of the struct, so
    /// we will too, to make it easy to convince ourselves it's correct.
    pub fn as_slice(&self) -> &[u8] {
        let p = self as *const _ as *const u8;
        unsafe { std::slice::from_raw_parts(p, size_of::<Self>()) }
    }
}

/// Structure sent in reply to group query.  Note that this struct is
/// sent also if the service is disabled or there is no record found.
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

impl GrResponseHeader {
    /// Serialize the header to bytes.
    ///
    /// The C implementations of nscd just take the address of the struct, so
    /// we will too, to make it easy to convince ourselves it's correct.
    pub fn as_slice(&self) -> &[u8] {
        let p = self as *const _ as *const u8;
        unsafe { std::slice::from_raw_parts(p, size_of::<Self>()) }
    }
}
