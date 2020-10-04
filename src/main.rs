//! `nsncd` is a nscd-compatible daemon that proxies lookups, without caching.
//!
//! `nsncd` can be used in situations where you want to make an application use
//! nss plugins available to a different libc than the one the application will
//! load. Since most (all?) libc implementations will try to use
//! `/var/run/nscd/socket` if it exists, you can make all lookups on a machine
//! attempt to use the libc that nsncd is running with (and any nss plugins
//! available to it), regardless of the libc used by a particular application.
//!
//! `nsncd` currently does all its lookups directly in its own process, handling
//! each request on a thread. If you have `nss` plugins that behave badly (leak
//! resources, are not thread safe, etc.), this may cause problems.
//!
//! The `unscd` project attempts to solve this by handling lookup requests in
//! child processes instead of directly in the long-lived daemon. This isolates
//! the daemon from problems in the children doing the lookups, but the extra
//! overhead of forking additional child processes seems large. `unscd` can get
//! away with that because it's also caching, but we're not caching right now.
//! We might try forking child processes to handle requests at some point later.

// TODO:
// - implement other pw and group methods?
// - error handling
// - logging
// - maybe do serde better?
// - test errors in underlying calls
// - daemon/pidfile stuff

#[macro_use]
extern crate slog;
extern crate slog_async;
extern crate slog_term;

use std::io::prelude::*;
use std::os::unix::io::FromRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::thread;

use anyhow::{ensure, Context, Result};
use nix::libc;
use slog::Drain;
use systemd::daemon::{listen_fds, LISTEN_FDS_START};

mod handlers;
mod protocol;

/// Handle a new socket connection, reading the request and sending the response.
fn handle_stream(log: slog::Logger, mut stream: UnixStream) -> Result<()> {
    debug!(log, "accepted connection"; "stream" => ?stream);
    let mut buf = [0; 4096];
    let size_read = stream.read(&mut buf)?;
    let request = protocol::Request::parse(&buf[0..size_read])?;
    handlers::handle_request(log, &request, |s| stream.write_all(s).map_err(|e| e.into()))?;
    stream
        .shutdown(std::net::Shutdown::Both)
        .context("shutting down stream")?;
    Ok(())
}

extern "C" {
    fn __nss_disable_nscd(hell: unsafe extern "C" fn(u64, *mut libc::c_void));
}

unsafe extern "C" fn do_nothing(_dbidx: u64, _finfo: *mut libc::c_void) {}

fn main() -> Result<()> {
    unsafe {
        __nss_disable_nscd(do_nothing);
    }

    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain).build().fuse();

    let _log = slog::Logger::root(drain, o!());

    ensure!(listen_fds(true)? == 1, "expected one listen fd");
    let listener = unsafe { UnixListener::from_raw_fd(LISTEN_FDS_START) };

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                thread::spawn({
                    let log = _log.clone();
                    let log2 = _log.clone();
                    move || match handle_stream(log, stream) {
                        Ok(_) => {}
                        Err(err) => {
                            error!(log2, "error handling connection"; "err" => %err);
                        }
                    }
                });
            }
            Err(err) => {
                error!(_log, "error accepting connection"; "err" => %err);
                break;
            }
        }
    }

    Ok(())
}
