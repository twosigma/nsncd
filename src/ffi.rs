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

use nix::libc;

type size_t = ::std::os::raw::c_ulonglong;

extern "C" {
    /// This is the function signature of the glibc internal function to
    /// disable using nscd for this process.
    fn __nss_disable_nscd(hell: unsafe extern "C" fn(size_t, *mut libc::c_void));
}

/// Copied from
/// [unscd](https://github.com/bytedance/unscd/blob/3a4df8de6723bc493e9cd94bb3e3fd831e48b8ca/nscd.c#L2469)
///
/// This internal glibc function is called to disable trying to contact nscd.
/// We _are_ nscd, so we need to do the lookups, and not recurse.
/// Until 2.14, this function was taking no parameters.
/// In 2.15, it takes a function pointer from hell.
unsafe extern "C" fn do_nothing(_dbidx: size_t, _finfo: *mut libc::c_void) {}

/// Disable nscd inside our own glibc to prevent recursion.
pub fn disable_internal_nscd() {
    unsafe {
        __nss_disable_nscd(do_nothing);
    }
}
