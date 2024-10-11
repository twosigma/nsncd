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

//! The nscd protocol definition (at least, the parts of it we care about).
//!
//! The response structs here only describe the format of the header of the
//! response. For each such response, if the lookup succeeded, there are
//! additional strings we need to send after the header. Those are dealt with in
//! `handlers::send_{user,group}`. For a full picture of the protocol, you will
//! need to read both.

use std::mem::size_of;
use std::{convert::TryInto, net::IpAddr};

use anyhow::{ensure, Context, Result};
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::FromPrimitive;

use nix::libc::{c_int, gid_t, uid_t};

/// This is version 2 of the glibc nscd protocol. The version is passed as part
/// of each message header.
pub const VERSION: i32 = 2;

/// Errors used in {Ai,Hst}ResponseHeader structs.
/// See NSCD's resolv/netdb.h for the complete list.
pub const H_ERRNO_NETDB_SUCCESS: i32 = 0;
#[allow(dead_code)]
pub const H_ERRNO_TRY_AGAIN: i32 = 2; // Non-Authoritative Host not found

/// Available services. This enum describes all service types the nscd protocol
/// knows about, though we only implement `GETPW*`, `GETGR*`, and `INITGROUPS`.
#[derive(Clone, Copy, Debug, FromPrimitive, ToPrimitive)]
#[allow(clippy::upper_case_acronyms)]
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
    pub key: &'a [u8],
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

        Ok(Request {
            ty,
            key: &buf[12..key_end],
        })
    }
}

// the nscd protocol just puts structs onto a socket and hopes they come out
// the same size on the other end. it seems to assume there is no padding
// interpreted by the compiler.
//
// this is pretty sketchy, but we have to match it, so all of the structs
// below use repr(C) and not repr(padded).

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

/// Structure sent in reply to initgroups query.  Note that this struct is
/// sent also if the service is disabled or there is no record found.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct InitgroupsResponseHeader {
    pub version: c_int,
    pub found: c_int,
    pub ngrps: c_int,
}

impl InitgroupsResponseHeader {
    /// Serialize the header to bytes.
    ///
    /// The C implementations of nscd just take the address of the struct, so
    /// we will too, to make it easy to convince ourselves it's correct.
    pub fn as_slice(&self) -> &[u8] {
        let p = self as *const _ as *const u8;
        unsafe { std::slice::from_raw_parts(p, size_of::<Self>()) }
    }
}

/// Structure containing the resulting data of a [RequestType::GETAI]
/// operation.
///
/// Unlike most of the data types declared in this module, this
/// structure isn't meant to be directly serialized to the wire.
/// Instead, it contains all the necessary informations to to generate
/// a [AiResponseHeader] and its associated payload.
#[derive(Debug, Clone)]
pub struct AiResponse {
    pub addrs: Vec<IpAddr>,
    pub canon_name: String,
}

/// Response Header derived from the glibc `ai_response_header`
/// structure.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct AiResponseHeader {
    pub version: c_int,
    pub found: c_int,
    pub naddrs: c_int,
    pub addrslen: c_int,
    pub canonlen: c_int,
    pub error: c_int,
}

impl AiResponseHeader {
    /// Serialize the header to bytes
    ///
    /// The C implementations of nscd just take the address of the struct, so
    /// we will too, to make it easy to convince ourselves it's correct.
    pub fn as_slice(&self) -> &[u8] {
        let p = self as *const _ as *const u8;
        unsafe { std::slice::from_raw_parts(p, size_of::<Self>()) }
    }
}

/// Magic address info header returned to the client when an address
/// lookup doesn't yield any matches. See glib's `nscd/aicache.c` file
/// for the original definition.
pub const AI_RESPONSE_HEADER_NOT_FOUND: AiResponseHeader = AiResponseHeader {
    version: VERSION,
    found: 0,
    naddrs: 0,
    addrslen: 0,
    canonlen: 0,
    error: 0,
};

/// Structure used to hold the reply header of a
/// gethostbyaddr[v6]/gethostbyname[v6] request.
/// Maps to the hst_response_header struct in nscd.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct HstResponseHeader {
    pub version: c_int,
    pub found: c_int,           // 0 or 1, -1 if disabled
    pub h_name_len: c_int,      // length of the hostname null-terminated
    pub h_aliases_cnt: c_int,   // number of aliases (0)
    pub h_addrtype: c_int,      // AF_INET or AF_INET6
    pub h_length: c_int,        // length of the address
    pub h_addr_list_cnt: c_int, // number of addresses (1)
    pub error: c_int,           // H_ERRNO_*
}

impl HstResponseHeader {
    /// Serialize the header to bytes.
    ///
    /// The C implementations of nscd just take the address of the struct, so
    /// we will too, to make it easy to convince ourselves it's correct.
    pub fn as_slice(&self) -> &[u8] {
        let p = self as *const _ as *const u8;
        unsafe { std::slice::from_raw_parts(p, size_of::<Self>()) }
    }
}

/* Structure send in reply to innetgroup query.  Note that this struct is
sent also if the service is disabled or there is no record found.  */
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct InNetgroupResponseHeader {
    pub version: c_int,
    pub found: c_int,
    pub result: c_int,
}

impl InNetgroupResponseHeader {
    /// Serialize the header to bytes.
    ///
    /// The C implementations of nscd just take the address of the struct, so
    /// we will too, to make it easy to convince ourselves it's correct.
    pub fn as_slice(&self) -> &[u8] {
        let p = self as *const _ as *const u8;
        unsafe { std::slice::from_raw_parts(p, size_of::<Self>()) }
    }
}

/* Structure send in reply to service query.  Note that this struct is
sent also if the service is disabled or there is no record found.  */

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ServResponseHeader {
    pub version: c_int,
    pub found: c_int,
    pub s_name_len: c_int,
    pub s_proto_len: c_int,
    pub s_aliases_cnt: c_int,
    pub s_port: c_int,
}

/* Structure send in reply to netgroup query.  Note that this struct is
sent also if the service is disabled or there is no record found.  */
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct NetgroupResponseHeader {
    pub version: c_int,
    pub found: c_int,
    pub nresults: c_int,
    pub result_len: c_int,
}

impl ServResponseHeader {
    pub fn as_slice(&self) -> &[u8] {
        let p = self as *const _ as *const u8;
        unsafe { std::slice::from_raw_parts(p, size_of::<Self>()) }
    }
}

impl NetgroupResponseHeader {
    pub fn as_slice(&self) -> &[u8] {
        let p = self as *const _ as *const u8;
        unsafe { std::slice::from_raw_parts(p, size_of::<Self>()) }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_pw_response_header_as_slice() {
        let header = PwResponseHeader {
            version: VERSION,
            found: 1,
            pw_name_len: 5,
            pw_passwd_len: 0,
            pw_uid: 123,
            pw_gid: 456,
            pw_gecos_len: 666,
            pw_dir_len: 888,
            pw_shell_len: 4,
        };

        let mut expected = Vec::with_capacity(4 * 9);
        {
            expected.extend_from_slice(&VERSION.to_ne_bytes());
            expected.extend_from_slice(&1i32.to_ne_bytes());
            expected.extend_from_slice(&5i32.to_ne_bytes());
            expected.extend_from_slice(&0i32.to_ne_bytes());
            expected.extend_from_slice(&123u32.to_ne_bytes());
            expected.extend_from_slice(&456u32.to_ne_bytes());
            expected.extend_from_slice(&666i32.to_ne_bytes());
            expected.extend_from_slice(&888i32.to_ne_bytes());
            expected.extend_from_slice(&4i32.to_ne_bytes());
        }

        assert_eq!(header.as_slice(), expected);
    }

    #[test]
    fn gr_response_header_as_slice() {
        let header = GrResponseHeader {
            version: VERSION,
            found: 1,
            gr_name_len: 5,
            gr_passwd_len: 0,
            gr_gid: 420,
            gr_mem_cnt: 1,
        };

        let mut expected = Vec::with_capacity(4 * 6);
        {
            expected.extend_from_slice(&VERSION.to_ne_bytes());
            expected.extend_from_slice(&1i32.to_ne_bytes());
            expected.extend_from_slice(&5i32.to_ne_bytes());
            expected.extend_from_slice(&0i32.to_ne_bytes());
            expected.extend_from_slice(&420u32.to_ne_bytes());
            expected.extend_from_slice(&1i32.to_ne_bytes());
        }

        assert_eq!(header.as_slice(), expected);
    }

    #[test]
    fn initgroups_response_header_as_slice() {
        let header = InitgroupsResponseHeader {
            version: VERSION,
            found: 1,
            ngrps: 10,
        };

        let mut expected = Vec::with_capacity(4 * 3);
        {
            expected.extend_from_slice(&VERSION.to_ne_bytes());
            expected.extend_from_slice(&1i32.to_ne_bytes());
            expected.extend_from_slice(&10i32.to_ne_bytes());
        }

        assert_eq!(header.as_slice(), expected);
    }
}
