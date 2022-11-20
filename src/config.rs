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

use std::env;
use std::time::Duration;

use anyhow::{Context, Result};

use super::protocol::RequestType;

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

impl Config {
    pub fn from_env() -> Result<Self> {
        Ok(Self {
            worker_count: env_usize("NSNCD_WORKER_COUNT", 8)?,
            handoff_timeout: Duration::from_secs(env_usize("NSNCD_HANDOFF_TIMEOUT", 3)? as u64),
            ignore_getpwbyname: env_bool("NSNCD_IGNORE_GETPWBYNAME")?,
            ignore_getpwbyuid: env_bool("NSNCD_IGNORE_GETPWBYUID")?,
            ignore_getgrbyname: env_bool("NSNCD_IGNORE_GETGRBYNAME")?,
            ignore_getgrbygid: env_bool("NSNCD_IGNORE_GETGRBYGID")?,
            ignore_initgroups: env_bool("NSNCD_IGNORE_INITGROUPS")?,
            ignore_gethostbyaddr: env_bool("NSNCD_IGNORE_GETHOSTBYADDR")?,
            ignore_gethostbyaddrv6: env_bool("NSNCD_IGNORE_GETHOSTBYADDRV6")?,
            ignore_gethostbyname: env_bool("NSNCD_IGNORE_GETHOSTBYNAME")?,
            ignore_gethostbynamev6: env_bool("NSNCD_IGNORE_GETHOSTBYNAMEV6")?,
            ignore_shutdown: env_bool("NSNCD_IGNORE_SHUTDOWN")?,
            ignore_getstat: env_bool("NSNCD_IGNORE_GETSTAT")?,
            ignore_invalidate: env_bool("NSNCD_IGNORE_INVALIDATE")?,
            ignore_getfdpw: env_bool("NSNCD_IGNORE_GETFDPW")?,
            ignore_getfdgr: env_bool("NSNCD_IGNORE_GETFDGR")?,
            ignore_getfdhst: env_bool("NSNCD_IGNORE_GETFDHST")?,
            ignore_getai: env_bool("NSNCD_IGNORE_GETAI")?,
            ignore_getservbyname: env_bool("NSNCD_IGNORE_GETSERVBYNAME")?,
            ignore_getservbyport: env_bool("NSNCD_IGNORE_GETSERVBYPORT")?,
            ignore_getfdserv: env_bool("NSNCD_IGNORE_GETFDSERV")?,
            ignore_getfdnetgr: env_bool("NSNCD_IGNORE_GETFDNETGR")?,
            ignore_getnetgrent: env_bool("NSNCD_IGNORE_GETNETGRENT")?,
            ignore_innetgr: env_bool("NSNCD_IGNORE_INNETGR")?,
        })
    }

    pub fn should_ignore(&self, ty: &RequestType) -> bool {
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

fn env_usize(var: &'static str, default: usize) -> Result<usize> {
    if let Ok(v) = env::var(var) {
        Ok(v.parse()
            .with_context(|| format!("parsing int from {}", v))?)
    } else {
        Ok(default)
    }
}

fn env_bool(var: &'static str) -> Result<bool> {
    if let Ok(v) = env::var(var) {
        Ok(v.parse()
            .with_context(|| format!("parsing bool from {}", v))?)
    } else {
        Ok(false)
    }
}
