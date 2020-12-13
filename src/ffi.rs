use nix::libc;

extern "C" {
    /// This is the function signature of the glibc internal function to
    /// disable using nscd for this process.
    fn __nss_disable_nscd(hell: unsafe extern "C" fn(u64, *mut libc::c_void));
}

/// Copied from
/// [unscd](https://github.com/bytedance/unscd/blob/3a4df8de6723bc493e9cd94bb3e3fd831e48b8ca/nscd.c#L2469)
///
/// This internal glibc function is called to disable trying to contact nscd.
/// We _are_ nscd, so we need to do the lookups, and not recurse.
/// Until 2.14, this function was taking no parameters.
/// In 2.15, it takes a function pointer from hell.
unsafe extern "C" fn do_nothing(_dbidx: u64, _finfo: *mut libc::c_void) {}

/// Disable nscd inside our own glibc to prevent recursion.
pub fn disable_internal_nscd() {
    unsafe {
        __nss_disable_nscd(do_nothing);
    }
}
