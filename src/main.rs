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
use std::time::Duration;

use anyhow::{Context, Result};
use crossbeam_channel as channel;
use slog::{debug, error, o, Drain};
use threadpool::ThreadPool;

mod ffi;
mod handlers;
mod protocol;

fn main() -> Result<()> {
    const SOCKET_PATH: &str = "/var/run/nscd/socket";
    const N_WORKERS: usize = 256;
    const HANDOFF_TIMEOUT: Duration = Duration::from_secs(3);

    ffi::disable_internal_nscd();

    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain).build().fuse();

    let logger = slog::Logger::root(drain, slog::o!());

    let (pool, handle) = worker_pool(logger.clone(), N_WORKERS);

    let path = Path::new(SOCKET_PATH);
    std::fs::create_dir_all(path.parent().expect("socket path has no parent"))?;
    std::fs::remove_file(path).ok();
    let listener = UnixListener::bind(path).context("could not bind to socket")?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o777))?;

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                // if something goes wrong and it's multiple seconds until we
                // get a response, kill the process.
                //
                // the timeout here is set such that nss will fall back to system
                // libc before this timeout is hit - clients will already be
                // giving up and going elsewhere so crashing the process should
                // not make a bad situation worse.
                match handle.send_timeout(stream, HANDOFF_TIMEOUT) {
                    Err(channel::SendTimeoutError::Timeout(_)) => {
                        anyhow::bail!("timed out waiting for an available worker: exiting")
                    }
                    Err(channel::SendTimeoutError::Disconnected(_)) => {
                        anyhow::bail!("aborting: worker channel is disconnected")
                    }
                    _ => { /*ok!*/ }
                }
            }
            Err(err) => {
                error!(logger, "error accepting connection"; "err" => %err);
                break;
            }
        }
    }

    // drop the worker handle so that the worker pool shuts down. every worker
    // task should break and the process should exit.
    std::mem::drop(handle);
    pool.join();

    Ok(())
}

fn worker_pool(log: slog::Logger, n_workers: usize) -> (ThreadPool, channel::Sender<UnixStream>) {
    let pool = ThreadPool::new(n_workers);
    let (tx, rx) = channel::bounded(0);

    // TODO: figure out how to name the worker threads in each worker
    // TODO: report actively working threads
    for _ in 0..n_workers {
        let log = log.clone();
        let rx = rx.clone();

        pool.execute(move || loop {
            let log = log.clone();
            match rx.recv() {
                Ok(stream) => handle_stream(log, stream),
                Err(channel::RecvError) => break,
            }
        });
    }

    (pool, tx)
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

#[cfg(test)]
mod pool_test {
    use super::*;

    #[test]
    fn worker_shutdown() {
        let logger = {
            let decorator = slog_term::PlainDecorator::new(slog_term::TestStdoutWriter);
            let drain = slog_term::FullFormat::new(decorator).build().fuse();
            let drain = slog_async::Async::new(drain).build().fuse();
            slog::Logger::root(drain, slog::o!())
        };

        let (pool, handle) = worker_pool(logger, 123);

        std::mem::drop(handle);
        pool.join();
    }
}
