/*
 * Copyright 2022 Two Sigma Open Source, LLC
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

//! Command line flags (to control which requests we respond to).

use std::time::Duration;

use clap::{App, Arg};

use super::protocol::RequestType;

pub trait RequestTypeIgnorer {
    fn should_ignore(&self, ty: &RequestType) -> bool;
}

pub trait Parser {
    fn parse() -> Result<Self, std::num::ParseIntError>
    where
        Self: std::marker::Sized;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Config {
    pub worker_count: usize,
    pub handoff_timeout: Duration,
    ignore_getpwbyname: bool,
    ignore_getpwbyuid: bool,
    ignore_getgrbyname: bool,
    ignore_getgrbygid: bool,
    ignore_initgroups: bool,
    ignore_gethostbyaddr: bool,
    ignore_gethostbyaddrv6: bool,
    ignore_gethostbyname: bool,
    ignore_gethostbynamev6: bool,
    ignore_shutdown: bool,
    ignore_getstat: bool,
    ignore_invalidate: bool,
    ignore_getfdpw: bool,
    ignore_getfdgr: bool,
    ignore_getfdhst: bool,
    ignore_getai: bool,
    ignore_getservbyname: bool,
    ignore_getservbyport: bool,
    ignore_getfdserv: bool,
    ignore_getfdnetgr: bool,
    ignore_getnetgrent: bool,
    ignore_innetgr: bool,
}

impl Parser for Config {
    fn parse() -> Result<Self, std::num::ParseIntError> {
        let m = App::new("nsncd")
            .args(&[
                Arg::with_name("worker_count")
                    .long("worker-count")
                    .env("NSNCD_WORKER_COUNT")
                    .default_value("8"),
                Arg::with_name("handoff_timeout")
                    .long("handoff-timeout")
                    .env("NSNCD_HANDOFF_TIMEOUT")
                    .default_value("3"),
                Arg::with_name("ignore_getpwbyname").long("ignore-getpwbyname"),
                Arg::with_name("ignore_getpwbyuid").long("ignore-getpwbyuid"),
                Arg::with_name("ignore_getgrbyname").long("ignore-getgrbyname"),
                Arg::with_name("ignore_getgrbygid").long("ignore-getgrbygid"),
                Arg::with_name("ignore_initgroups").long("ignore-initgroups"),
                Arg::with_name("ignore_gethostbyaddr").long("ignore-gethostbyaddr"),
                Arg::with_name("ignore_gethostbyaddrv6").long("ignore-gethostbyaddrv6"),
                Arg::with_name("ignore_gethostbyname").long("ignore-gethostbyname"),
                Arg::with_name("ignore_gethostbynamev6").long("ignore-gethostbynamev6"),
                Arg::with_name("ignore_shutdown").long("ignore-shutdown"),
                Arg::with_name("ignore_getstat").long("ignore-getstat"),
                Arg::with_name("ignore_invalidate").long("ignore-invalidate"),
                Arg::with_name("ignore_getfdpw").long("ignore-getfdpw"),
                Arg::with_name("ignore_getfdgr").long("ignore-getfdgr"),
                Arg::with_name("ignore_getfdhst").long("ignore-getfdhst"),
                Arg::with_name("ignore_getai").long("ignore-getai"),
                Arg::with_name("ignore_getservbyname").long("ignore-getservbyname"),
                Arg::with_name("ignore_getservbyport").long("ignore-getservbyport"),
                Arg::with_name("ignore_getfdserv").long("ignore-getfdserv"),
                Arg::with_name("ignore_getfdnetgr").long("ignore-getfdnetgr"),
                Arg::with_name("ignore_getnetgrent").long("ignore-getnetgrent"),
                Arg::with_name("ignore_innetgr").long("ignore-innetgr"),
            ])
            .get_matches();
        let worker_count = m.value_of("worker_count").unwrap().parse()?;
        let handoff_timeout = parse_duration(m.value_of("handoff_timeout").unwrap())?;
        Ok(Self {
            worker_count,
            handoff_timeout,
            ignore_getpwbyname: m.is_present("ignore_getpwbyname"),
            ignore_getpwbyuid: m.is_present("ignore_getpwbyuid"),
            ignore_getgrbyname: m.is_present("ignore_getgrbyname"),
            ignore_getgrbygid: m.is_present("ignore_getgrbygid"),
            ignore_initgroups: m.is_present("ignore_initgroups"),
            ignore_gethostbyaddr: m.is_present("ignore_gethostbyaddr"),
            ignore_gethostbyaddrv6: m.is_present("ignore_gethostbyaddrv6"),
            ignore_gethostbyname: m.is_present("ignore_gethostbyname"),
            ignore_gethostbynamev6: m.is_present("ignore_gethostbynamev6"),
            ignore_shutdown: m.is_present("ignore_shutdown"),
            ignore_getstat: m.is_present("ignore_getstat"),
            ignore_invalidate: m.is_present("ignore_invalidate"),
            ignore_getfdpw: m.is_present("ignore_getfdpw"),
            ignore_getfdgr: m.is_present("ignore_getfdgr"),
            ignore_getfdhst: m.is_present("ignore_getfdhst"),
            ignore_getai: m.is_present("ignore_getai"),
            ignore_getservbyname: m.is_present("ignore_getservbyname"),
            ignore_getservbyport: m.is_present("ignore_getservbyport"),
            ignore_getfdserv: m.is_present("ignore_getfdserv"),
            ignore_getfdnetgr: m.is_present("ignore_getfdnetgr"),
            ignore_getnetgrent: m.is_present("ignore_getnetgrent"),
            ignore_innetgr: m.is_present("ignore_innetgr"),
        })
    }
}

fn parse_duration(arg: &str) -> Result<std::time::Duration, std::num::ParseIntError> {
    let seconds = arg.parse()?;
    Ok(std::time::Duration::from_secs(seconds))
}

impl RequestTypeIgnorer for Config {
    fn should_ignore(&self, ty: &RequestType) -> bool {
        match ty {
            RequestType::GETPWBYNAME => self.ignore_getpwbyname,
            RequestType::GETPWBYUID => self.ignore_getpwbyuid,
            RequestType::GETGRBYNAME => self.ignore_getgrbyname,
            RequestType::GETGRBYGID => self.ignore_getgrbygid,
            RequestType::GETHOSTBYNAME => self.ignore_gethostbyname,
            RequestType::GETHOSTBYNAMEv6 => self.ignore_gethostbynamev6,
            RequestType::GETHOSTBYADDR => self.ignore_gethostbyaddr,
            RequestType::GETHOSTBYADDRv6 => self.ignore_gethostbyaddrv6,
            RequestType::SHUTDOWN => self.ignore_shutdown,
            RequestType::GETSTAT => self.ignore_getstat,
            RequestType::INVALIDATE => self.ignore_invalidate,
            RequestType::GETFDPW => self.ignore_getfdpw,
            RequestType::GETFDGR => self.ignore_getfdgr,
            RequestType::GETFDHST => self.ignore_getfdhst,
            RequestType::GETAI => self.ignore_getai,
            RequestType::INITGROUPS => self.ignore_initgroups,
            RequestType::GETSERVBYNAME => self.ignore_getservbyname,
            RequestType::GETSERVBYPORT => self.ignore_getservbyport,
            RequestType::GETFDSERV => self.ignore_getfdserv,
            RequestType::GETNETGRENT => self.ignore_getnetgrent,
            RequestType::INNETGR => self.ignore_innetgr,
            RequestType::GETFDNETGR => self.ignore_getfdnetgr,
            // This can't happen
            RequestType::LASTREQ => false,
        }
    }
}
