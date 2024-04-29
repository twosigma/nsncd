/*
 * Copyright 2020-2022 Two Sigma Open Source, LLC
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
use listenfd::ListenFd;
use sd_notify::NotifyState;
use slog::{debug, error, o, Drain};

mod config;
mod ffi;
mod handlers;
mod protocol;
mod work_group;

use config::Config;
use work_group::WorkGroup;

const SOCKET_PATH: &str = "/var/run/nscd/socket";

fn main() -> Result<()> {
    ffi::disable_internal_nscd();

    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain).build().fuse();

    let logger = slog::Logger::root(drain, slog::o!());

    let config = Config::from_env()?;

    // If we're started using socket activation, use the unix listener at index 0,
    // else bind manually on SOCKET_PATH.
    let (listener, listen_address) = match ListenFd::from_env()
        .take_unix_listener(0)
        .expect("invalid socket type at index")
    {
        Some(listener) => (listener, "sd-listen-unix"),
        None => {
            let path = Path::new(SOCKET_PATH);
            std::fs::create_dir_all(path.parent().expect("socket path has no parent"))?;
            std::fs::remove_file(path).ok();
            let listener = UnixListener::bind(path).context("could not bind to socket")?;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o777))?;

            (listener, SOCKET_PATH)
        }
    };

    slog::info!(logger, "started";
        "listen_address" => listen_address,
        "config" => ?config,
    );
    let mut wg = WorkGroup::new();
    let tx = spawn_workers(&mut wg, &logger, config);

    spawn_acceptor(&mut wg, &logger, listener, tx, config.handoff_timeout);

    let _ = sd_notify::notify(true, &[NotifyState::Ready]);

    let (result, handles) = wg.run();
    if let Err(e) = result {
        // if a thread unwound with a panic, just start panicing here. the nss
        // modules in this process space are probably very sad, and we'll
        // stop serving requests abruptly.
        std::panic::resume_unwind(e);
    } else {
        // something else happened that made a process exit, so try to exit
        // gracefully.
        slog::info!(logger, "shutting down");
        for handle in handles {
            let _ = handle.join();
        }
        Ok(())
    }
}

fn spawn_acceptor(
    wg: &mut WorkGroup,
    log: &slog::Logger,
    listener: UnixListener,
    tx: channel::Sender<UnixStream>,
    handoff_timeout: Duration,
) {
    let log = log.new(o!("thread" => "accept"));

    wg.add(move |ctx| {
        for stream in listener.incoming() {
            if ctx.is_shutdown() {
                break;
            }

            match stream {
                // if something goes wrong and it's multiple seconds until we
                // get a response, kill the process.
                //
                // the timeout here is set such that nss will fall back to system
                // libc before this timeout is hit - clients will already be
                // giving up and going elsewhere so crashing the process should
                // not make a bad situation worse.
                Ok(stream) => match tx.send_timeout(stream, handoff_timeout) {
                    Err(channel::SendTimeoutError::Timeout(_)) => {
                        error!(log, "timed out waiting for an available worker");
                        break;
                    }
                    Err(channel::SendTimeoutError::Disconnected(_)) => {
                        error!(log, "worker channel is disconnected");
                        break;
                    }
                    Ok(()) => { /*ok!*/ }
                },
                Err(err) => {
                    error!(log, "error accepting connection"; "err" => %err);
                    break;
                }
            }
        }

        // at the end of the listener loop, drop tx so that any working threads
        // still waiting for a connection have a chance to finish.
        //
        // this is unnecessary but explicit
        std::mem::drop(tx);
    });
}

fn spawn_workers(
    wg: &mut WorkGroup,
    log: &slog::Logger,
    config: Config,
) -> channel::Sender<UnixStream> {
    let (tx, rx) = channel::bounded(0);

    for worker_id in 0..config.worker_count {
        let rx = rx.clone();
        let log = log.new(o!("thread" => format!("worker_{}", worker_id)));

        // ctx is ignored - the acceptor thread will close the rx channel if
        // the wg is shutdown and it's time to exit.
        wg.add(move |_ctx| {
            while let Ok(stream) = rx.recv() {
                handle_stream(&log, &config, stream);
            }
        });
    }

    tx
}

fn handle_stream(log: &slog::Logger, config: &Config, mut stream: UnixStream) {
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
    let response = match handlers::handle_request(&log, config, &request) {
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
