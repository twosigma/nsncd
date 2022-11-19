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

use super::protocol::RequestType;

pub trait RequestTypeIgnorer {
    fn should_ignore(&self, ty: &RequestType) -> bool;
}

#[derive(clap::Parser, Clone, Copy, Debug, Default)]
pub struct Config {
    #[clap(long, env("NSNCD_WORKER_COUNT"), default_value_t = 8)]
    pub worker_count: usize,
    #[clap(long, env("NSNCD_HANDOFF_TIMEOUT"), default_value = "3", parse(try_from_str = parse_duration))]
    pub handoff_timeout: Duration,
    #[clap(long, env("NSNCD_IGNORE_GETPWBYNAME"))]
    ignore_getpwbyname: bool,
    #[clap(long, env("NSNCD_IGNORE_GETPWBYUID"))]
    ignore_getpwbyuid: bool,
    #[clap(long, env("NSNCD_IGNORE_GETGRBYNAME"))]
    ignore_getgrbyname: bool,
    #[clap(long, env("NSNCD_IGNORE_GETGRBYGID"))]
    ignore_getgrbygid: bool,
    #[clap(long, env("NSNCD_IGNORE_INITGROUPS"))]
    ignore_initgroups: bool,
    #[clap(long, env("NSNCD_IGNORE_GETHOSTBYADDR"))]
    ignore_gethostbyaddr: bool,
    #[clap(long, env("NSNCD_IGNORE_GETHOSTBYADDRV6"))]
    ignore_gethostbyaddrv6: bool,
    #[clap(long, env("NSNCD_IGNORE_GETHOSTBYNAME"))]
    ignore_gethostbyname: bool,
    #[clap(long, env("NSNCD_IGNORE_GETHOSTBYNAMEV6"))]
    ignore_gethostbynamev6: bool,
    #[clap(long, env("NSNCD_IGNORE_SHUTDOWN"))]
    ignore_shutdown: bool,
    #[clap(long, env("NSNCD_IGNORE_GETSTAT"))]
    ignore_getstat: bool,
    #[clap(long, env("NSNCD_IGNORE_INVALIDATE"))]
    ignore_invalidate: bool,
    #[clap(long, env("NSNCD_IGNORE_GETFDPW"))]
    ignore_getfdpw: bool,
    #[clap(long, env("NSNCD_IGNORE_GETFDGR"))]
    ignore_getfdgr: bool,
    #[clap(long, env("NSNCD_IGNORE_GETFDHST"))]
    ignore_getfdhst: bool,
    #[clap(long, env("NSNCD_IGNORE_GETAI"))]
    ignore_getai: bool,
    #[clap(long, env("NSNCD_IGNORE_GETSERVBYNAME"))]
    ignore_getservbyname: bool,
    #[clap(long, env("NSNCD_IGNORE_GETSERVBYPORT"))]
    ignore_getservbyport: bool,
    #[clap(long, env("NSNCD_IGNORE_GETFDSERV"))]
    ignore_getfdserv: bool,
    #[clap(long, env("NSNCD_IGNORE_GETFDNETGR"))]
    ignore_getfdnetgr: bool,
    #[clap(long, env("NSNCD_IGNORE_GETNETGRENT"))]
    ignore_getnetgrent: bool,
    #[clap(long, env("NSNCD_IGNORE_INNETGR"))]
    ignore_innetgr: bool,
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
