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

use std::env;
use std::io::ErrorKind;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use anyhow::{Context, Result};
use slog::{debug, error, o, Drain};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

mod ffi;
mod handlers;
mod protocol;

const SOCKET_PATH: &str = "/var/run/nscd/socket";

fn main() -> Result<()> {
    ffi::disable_internal_nscd();

    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain).build().fuse();

    let logger = slog::Logger::root(drain, slog::o!());

    // build a tokio runtime and immediately set it as the main-thread
    // runtime with enter. this lets us call functions that assume a
    // thread-local runtime exists, like UnixListener::bind
    let threads = env_usize("NSNCD_THREADS", 2);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(threads)
        .thread_name("nsncd")
        .enable_io()
        .enable_time()
        .build()
        .unwrap();
    let _rt_context = runtime.enter();

    // let worker_count = env_usize("NSNCD_WORKER_COUNT", 8);
    // let handoff_timeout = Duration::from_secs(env_usize("NSNCD_HANDOFF_TIMEOUT", 3) as u64);
    let path = Path::new(SOCKET_PATH);
    let listener = {
        // clean up the existing nscd socket
        std::fs::create_dir_all(path.parent().expect("socket path has no parent"))?;
        std::fs::remove_file(path).ok();

        // create a new one and permission it appropriately
        let listener = UnixListener::bind(path).context("could not bind to socket")?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o777))?;

        listener
    };

    slog::info!(logger, "started";
        "path" => ?path,
        "threads" => threads,
    );

    // FIXME: we have to do something to catch panics in the tasks that handle
    //        individual connections. our options seem to be:
    //        - figure out a way to do it ourselves
    //        - set panic = abort when building and not getting backtraces.
    //
    runtime.block_on(run(&logger, listener));
    Ok(())
}

fn env_usize(var: &'static str, default: usize) -> usize {
    if let Some(value) = env::var(var).ok().and_then(|v| v.parse().ok()) {
        value
    } else {
        default
    }
}

async fn run(log: &slog::Logger, listener: UnixListener) {
    let log = log.new(o!("task" => "accept"));

    loop {
        match listener.accept().await {
            // TODO: format remote addr and use it as a field in the logger passed
            //       to handle_stream
            Ok((stream, _addr)) => {
                let log = log.new(o!("task" => "handle"));
                tokio::spawn(handle_stream(log, stream));
            }
            Err(_) => {} // connection failed, move on
        }
    }
}

async fn handle_stream(log: slog::Logger, mut stream: UnixStream) {
    let mut buf = [0; 4096];
    let bytes_read = match stream.read(&mut buf).await {
        Ok(n) => n,
        Err(e) => {
            debug!(log, "error reading from conn"; "err" => %e);
            return;
        }
    };

    let request = match protocol::Request::parse(&buf[0..bytes_read]) {
        Ok(x) => x,
        Err(e) => {
            debug!(log, "parsing request"; "err" => %e);
            return;
        }
    };

    let response = match handlers::handle_request(&log, &request) {
        Ok(x) => x,
        Err(e) => {
            error!(log, "error handling request"; "err" => %e);
            return;
        }
    };

    if let Err(e) = stream.write_all(response.as_slice()).await {
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

    if let Err(e) = stream.shutdown().await {
        debug!(log, "shutting down stream"; "err" => %e);
    }
}
