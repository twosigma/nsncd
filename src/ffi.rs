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

use anyhow::anyhow;
use nix::libc::{self, dlsym, RTLD_DEFAULT};
use std::convert::TryInto;
use std::ffi::{CStr, CString};
use std::mem;
use std::ptr;

#[allow(non_camel_case_types)]
type size_t = ::std::os::raw::c_ulonglong;

/// Copied from
/// [unscd](https://github.com/bytedance/unscd/blob/3a4df8de6723bc493e9cd94bb3e3fd831e48b8ca/nscd.c#L2469)
///
/// This internal glibc function is called to disable trying to contact nscd.
/// We _are_ nscd, so we need to do the lookups, and not recurse.
/// Until 2.14, this function was taking no parameters.
/// In 2.15, it takes a function pointer from hell.
unsafe extern "C" fn do_nothing(_dbidx: size_t, _finfo: *mut libc::c_void) {}

/// Disable nscd inside our own glibc to prevent recursion.
/// Some versions of glibc, like the one Arch Linux provides, are built without
/// support for nscd, but the possibility remains that this support is
/// re-enabled in a later update.
///
/// This function loads the __nss_disable_nscd function through dlopen() with
/// RTLD_DEFAULT (to find it in libc) and calls it only if it was found.
pub fn disable_internal_nscd() {
    unsafe {
        let sym_name = CString::new("__nss_disable_nscd").unwrap();
        let sym_ptr = dlsym(RTLD_DEFAULT, sym_name.as_ptr());
        if !sym_ptr.is_null() {
            let __nss_disable_nscd = mem::transmute::<
                *mut libc::c_void,
                extern "C" fn(hell: unsafe extern "C" fn(size_t, *mut libc::c_void))
            >(sym_ptr);
            __nss_disable_nscd(do_nothing);
        }
    }
}

pub enum LibcIp {
    V4([u8; 4]),
    V6([u8; 16]),
}

mod glibcffi {
    use nix::libc;
    extern "C" {
        pub fn gethostbyname2_r(
            name: *const libc::c_char,
            af: libc::c_int,
            result_buf: *mut libc::hostent,
            buf: *mut libc::c_char,
            buflen: libc::size_t,
            result: *mut *mut libc::hostent,
            h_errnop: *mut libc::c_int,
        ) -> libc::c_int;

        pub fn gethostbyaddr_r(
            addr: *const libc::c_void,
            len: libc::socklen_t,
            af: libc::c_int,
            ret: *mut libc::hostent,
            buf: *mut libc::c_char,
            buflen: libc::size_t,
            result: *mut *mut libc::hostent,
            h_errnop: *mut libc::c_int,
        ) -> libc::c_int;
    }
}

/// This structure is the Rust counterpart of the `libc::hostent` C
/// function the Libc hostent struct.
///
/// It's mostly used to perform the gethostbyaddr and gethostbyname
/// operations.
///
/// This struct can be serialized to the wire through the
/// `serialize_hostent` function or retrieved from the C boundary using the
/// TryFrom `libc:hostent` trait.
#[derive(Clone, Debug)]
pub struct Hostent {
    pub name: CString,
    pub aliases: Vec<CString>,
    pub addr_type: i32,
    pub addr_list: Vec<std::net::IpAddr>,
    pub herrno: i32,
}

impl Hostent {
    /// Given a herrno, constructs the hostent header we're supposed to use to
    /// convey a lookup error.
    /// NOTE: herrno is different from errno.h.
    /// This is a glibc quirk, I have nothing to do with that, don't blame me :)
    pub fn error_value(herrno: i32) -> Self {
        // This is a default hostent header
        Hostent {
            name: CString::default(),
            aliases: Vec::new(),
            addr_type: -1,
            addr_list: Vec::new(),
            herrno,
        }
    }
}

/// Structure used to represent a gethostbyxxx error.
///
/// These operations can fail in two major ways: either they'll fail
/// returning a Hostent, in which case they return a HError code that
/// should be returned to the glibc client together with a dummy error
/// Hostent. Either as an "internal failure". In that case, we won't
/// be able to return anything to the GLibc client.
#[derive(Debug)]
pub enum HostentError {
    HError(i32),
    Other(anyhow::Error)
}

fn from_libc_hostent(value: libc::hostent) -> Result<Hostent, HostentError> {
    // validate value.h_addtype, and bail out if it's unsupported
    if value.h_addrtype != libc::AF_INET && value.h_addrtype != libc::AF_INET6 {
        return Err(HostentError::Other(anyhow!("unsupported address type: {}", value.h_addrtype)));
    }

    // ensure value.h_length matches what we know from this address family
    if value.h_addrtype == libc::AF_INET && value.h_length != 4 {
        return Err(HostentError::Other(anyhow!("unsupported h_length for AF_INET: {}", value.h_length)));
    }
    if value.h_addrtype == libc::AF_INET6 && value.h_length != 16 {
        return Err(HostentError::Other(anyhow!("unsupported h_length for AF_INET6: {}", value.h_length)));
    }

    // construct the name field.
    // Be careful about null pointers or invalid utf-8 strings, even though this
    // shouldn't happen.
    if value.h_name.is_null() {
        return Err(HostentError::Other(anyhow!("h_name is null")));
    }
    let name = unsafe { CStr::from_ptr(value.h_name) };

    // construct the list of aliases. keep adding to value.h_aliases until we encounter a null pointer.
    let mut aliases: Vec<CString> = Vec::new();
    let mut h_alias_ptr = value.h_aliases as *const *const libc::c_char;
    while !(unsafe { *h_alias_ptr }).is_null() {
        aliases.push(unsafe { CStr::from_ptr(*h_alias_ptr).to_owned() });
        // increment
        unsafe {
            h_alias_ptr = h_alias_ptr.add(1);
        }
    }

    // construct the list of addresses.
    let mut addr_list: Vec<std::net::IpAddr> = Vec::new();

    // [value.h_addr_list] is a pointer to a list of pointers to addresses.
    // h_addr_list[0] => ptr to first address
    // h_addr_list[n] => null pointer (end of list)
    let mut h_addr_ptr = value.h_addr_list as *const *const libc::c_void;
    while !(unsafe { *h_addr_ptr }).is_null() {
        if value.h_addrtype == libc::AF_INET {
            let octets: [u8; 4] = unsafe { std::ptr::read((*h_addr_ptr) as *const [u8; 4]) };
            addr_list.push(std::net::IpAddr::V4(std::net::Ipv4Addr::from(octets)));
        } else {
            let octets: [u8; 16] = unsafe { std::ptr::read((*h_addr_ptr) as *const [u8; 16]) };
            addr_list.push(std::net::IpAddr::V6(std::net::Ipv6Addr::from(octets)));
        }
        unsafe { h_addr_ptr = h_addr_ptr.add(1) };
    }

    Ok(Hostent {
        name: name.to_owned(),
        aliases,
        addr_type: value.h_addrtype,
        addr_list,
        // If we're here, glibc gave us an hostent. We should discard herrno to match the nscd behaviour.
        herrno: 0,
    })
}

/// Decodes the result of a gethostbyname/addr call into a `Hostent`
/// Rust struct.
///
/// This decoding algorithm is quite confusing, but that's how it's
/// implemented in Nscd and what the client Glibc expects. We
/// basically always ignore `herrno` except if the resulting
/// `libc::hostent` is set to null by glibc.
fn unmarshal_gethostbyxx(
    hostent: *mut libc::hostent,
    herrno: libc::c_int,
) -> Result<Hostent, HostentError> {
    if !hostent.is_null() {
        let res = from_libc_hostent(unsafe { *hostent })?;
        Ok(res)
    } else {
        Err(HostentError::HError(herrno))
    }
}

pub fn gethostbyaddr_r(addr: LibcIp) -> Result<Hostent, HostentError> {
    let (addr, len, af) = match addr {
        LibcIp::V4(ref ipv4) => (ipv4 as &[u8], 4, libc::AF_INET),
        LibcIp::V6(ref ipv6) => (ipv6 as &[u8], 16, libc::AF_INET6),
    };

    let mut ret_hostent: libc::hostent = libc::hostent {
        h_name: ptr::null_mut(),
        h_aliases: ptr::null_mut(),
        h_addrtype: 0,
        h_length: 0,
        h_addr_list: ptr::null_mut(),
    };
    let mut herrno: libc::c_int = 0;
    let mut hostent_result = ptr::null_mut();
    // We start with a 1024 bytes buffer, the nscd default. See
    // scratch_buffer.h in the glibc codebase
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    loop {
        let ret = unsafe {
            glibcffi::gethostbyaddr_r(
                addr.as_ptr() as *const libc::c_void,
                len,
                af,
                &mut ret_hostent,
                buf.as_mut_ptr() as *mut libc::c_char,
                (buf.capacity() as size_t).try_into().unwrap(),
                &mut hostent_result,
                &mut herrno,
            )
        };

        if ret == libc::ERANGE && buf.capacity() < 10 * 1000 * 1000 {
            buf.reserve(buf.capacity() * 2);
        } else {
            break;
        }
    }
    unmarshal_gethostbyxx(hostent_result, herrno)
}

/// Typesafe wrapper around the gethostbyname2_r glibc function
///
/// af is either nix::libc::AF_INET or nix::libc::AF_INET6
pub fn gethostbyname2_r(name: String, af: libc::c_int) -> Result<Hostent, HostentError> {
    let name = CString::new(name).unwrap();

    // Prepare a libc::hostent and the pointer to the result list,
    // which will be passed to the glibcffi::gethostbyname2_r call.
    let mut ret_hostent: libc::hostent = libc::hostent {
        h_name: ptr::null_mut(),
        h_aliases: ptr::null_mut(),
        h_addrtype: 0,
        h_length: 0,
        h_addr_list: ptr::null_mut(),
    };
    let mut herrno: libc::c_int = 0;
    // The 1024 initial size comes from the Glibc default. It fit most
    // of the requests in practice.
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    let mut hostent_result = ptr::null_mut();
    loop {
        let ret = unsafe {
            glibcffi::gethostbyname2_r(
                name.as_ptr(),
                af,
                &mut ret_hostent,
                buf.as_mut_ptr() as *mut libc::c_char,
                (buf.capacity() as size_t).try_into().unwrap(),
                &mut hostent_result,
                &mut herrno,
            )
        };
        if ret == libc::ERANGE {
            // The buffer is too small. Let's x2 its capacity and retry.
            buf.reserve(buf.capacity() * 2);
        } else {
            break;
        }
    }
    unmarshal_gethostbyxx(hostent_result, herrno)
}

#[test]
fn test_gethostbyname2_r() {
    disable_internal_nscd();

    let result =
        gethostbyname2_r("localhost.".to_string(), libc::AF_INET);
    result.expect("Should resolve IPv4 localhost.");

    let result =
        gethostbyname2_r("localhost.".to_string(), libc::AF_INET6);
    result.expect("Should resolve IPv6 localhost.");
}

#[test]
fn test_gethostbyaddr_r() {
    disable_internal_nscd();

    let v4test = LibcIp::V4([127, 0, 0, 1]);
    let _ = gethostbyaddr_r(v4test).expect("Should resolve IPv4 localhost with gethostbyaddr");

    let v6test = LibcIp::V6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    let _ = gethostbyaddr_r(v6test).expect("Should resolve IPv6 localhost with gethostbyaddr");
}
