// TODO:
// - implement other pw and group methods?
// - error handling
// - logging
// - maybe do serde better?
// - test errors in underlying calls
// - daemon/pidfile stuff

#![feature(array_methods)]

#[macro_use]
extern crate slog;
extern crate slog_async;
extern crate slog_term;

use std::io::prelude::*;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::thread;

use anyhow::{Context, Result};
use nix::libc;
use slog::Drain;

mod handlers;
mod protocol;

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

const SOCKET_PATH: &str = "/var/run/nscd/socket";

fn main() -> Result<()> {
    unsafe {
        __nss_disable_nscd(do_nothing);
    }

    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain).build().fuse();

    let _log = slog::Logger::root(drain, o!());

    std::fs::remove_file(SOCKET_PATH).ok();
    let listener = UnixListener::bind(SOCKET_PATH)?;
    std::fs::set_permissions(SOCKET_PATH, std::fs::Permissions::from_mode(0o777))?;

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
