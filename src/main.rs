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

//! `nsncd` is a nscd-compatible daemon that proxies lookups, without caching.
//!
//! `nsncd` stands for "Name Service Non-Caching Daemon."
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

use std::io::prelude::*;
use std::io::ErrorKind;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};
use slog::{debug, error, o, Drain};

mod ffi;
mod handlers;
mod protocol;
mod semaphore;

const SOCKET_PATH: &str = "/var/run/nscd/socket";
const MAX_THREADS: usize = 64;
const MAX_THREADS_WAIT_TIMEOUT: Duration = Duration::from_secs(5);

fn main() -> Result<()> {
    ffi::disable_internal_nscd();

    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain).build().fuse();

    let logger = slog::Logger::root(drain, slog::o!());

    let path = Path::new(SOCKET_PATH);
    std::fs::create_dir_all(path.parent().expect("socket path has no parent"))?;
    std::fs::remove_file(path).ok();
    let listener = UnixListener::bind(path).context("could not bind to socket")?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o777))?;

    let sem = semaphore::Semaphore::new(MAX_THREADS);

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let thread_logger = logger.clone();

                // block on acquring a permit before spawning the thread so
                // that we actually limit the number of threads used.
                let permit = match sem.acquire(MAX_THREADS_WAIT_TIMEOUT) {
                    Ok(p) => p,
                    Err(_) => {
                        anyhow::bail!("timed out waiting to spawn a handler thread. blowing up!")
                    }
                };

                thread::spawn(move || {
                    let _permit = permit;
                    handle_stream(thread_logger, stream);
                });
            }
            Err(err) => {
                error!(logger, "error accepting connection"; "err" => %err);
                break;
            }
        }
    }

    Ok(())
}

/// Handle a new socket connection, reading the request and sending the response.
fn handle_stream(log: slog::Logger, mut stream: UnixStream) {
    debug!(log, "accepted connection"; "stream" => ?stream);
    let mut buf = [0; 4096];
    let size_read = match stream.read(&mut buf) {
        Ok(x) => x,
        Err(e) => {
            debug!(log, "reading from connection"; "err" => %e);
            return;
        }
    };
    let request = match protocol::Request::parse(&buf[0..size_read]) {
        Ok(x) => x,
        Err(e) => {
            debug!(log, "parsing request"; "err" => %e);
            return;
        }
    };
    let type_str = format!("{:?}", request.ty);
    let log = log.new(o!("request_type" => type_str));
    let response = match handlers::handle_request(&log, &request) {
        Ok(x) => x,
        Err(e) => {
            error!(log, "error handling request"; "err" => %e);
            return;
        }
    };
    if let Err(e) = stream.write_all(response.as_slice()) {
        match e.kind() {
            // If we send a response that's too big for the client's buffer,
            // the client will disconnect and not read the rest of our
            // response, and then come back with a new connection after
            // increasing its buffer. There's no need to log that, and
            // generally, clients can disappear at any point.
            ErrorKind::ConnectionReset | ErrorKind::BrokenPipe => (),
            _ => debug!(log, "sending response"; "response_len" => response.len(), "err" => %e),
        };
    }
    if let Err(e) = stream.shutdown(std::net::Shutdown::Both) {
        debug!(log, "shutting down stream"; "err" => %e);
    }
}
