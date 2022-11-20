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

#[derive(Clone, Copy, Debug)]
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
            worker_count: env_positive_usize("NSNCD_WORKER_COUNT", 8)?,
            handoff_timeout: Duration::from_secs(
                env_positive_usize("NSNCD_HANDOFF_TIMEOUT", 3)? as u64
            ),
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

impl Default for Config {
    fn default() -> Self {
        Self {
            worker_count: 8,
            handoff_timeout: Duration::from_secs(3),
            ignore_getpwbyname: Default::default(),
            ignore_getpwbyuid: Default::default(),
            ignore_getgrbyname: Default::default(),
            ignore_getgrbygid: Default::default(),
            ignore_initgroups: Default::default(),
            ignore_gethostbyaddr: Default::default(),
            ignore_gethostbyaddrv6: Default::default(),
            ignore_gethostbyname: Default::default(),
            ignore_gethostbynamev6: Default::default(),
            ignore_shutdown: Default::default(),
            ignore_getstat: Default::default(),
            ignore_invalidate: Default::default(),
            ignore_getfdpw: Default::default(),
            ignore_getfdgr: Default::default(),
            ignore_getfdhst: Default::default(),
            ignore_getai: Default::default(),
            ignore_getservbyname: Default::default(),
            ignore_getservbyport: Default::default(),
            ignore_getfdserv: Default::default(),
            ignore_getfdnetgr: Default::default(),
            ignore_getnetgrent: Default::default(),
            ignore_innetgr: Default::default(),
        }
    }
}

fn env_positive_usize(var: &'static str, default: usize) -> Result<usize> {
    if let Ok(v) = env::var(var) {
        let val = v
            .parse()
            .with_context(|| format!("parsing int from {}", v))?;
        if val > 0 {
            Ok(val)
        } else {
            Err(anyhow::format_err!("variable {} cannot be 0", var))
        }
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

#[cfg(test)]
mod test {
    use std::time::Duration;

    use temp_env::{with_var, with_var_unset, with_vars};

    use super::Config;

    #[test]
    fn test_defaults() {
        let config = Config::default();
        assert_eq!(config.worker_count, 8);
        assert_eq!(config.handoff_timeout, Duration::from_secs(3));
        assert!(!config.ignore_getpwbyname);
        assert!(!config.ignore_getpwbyuid);
    }

    #[test]
    fn test_worker_count() {
        with_var_unset("NSNCD_WORKER_COUNT", || {
            let config = Config::from_env().unwrap();
            assert_eq!(config.worker_count, Config::default().worker_count);
        });
        with_var("NSNCD_WORKER_COUNT", Some("13"), || {
            let config = Config::from_env().unwrap();
            assert_eq!(config.worker_count, 13);
        });
        with_var("NSNCD_WORKER_COUNT", Some("0"), || {
            assert!(Config::from_env().is_err());
        });
        with_var("NSNCD_WORKER_COUNT", Some("-1"), || {
            assert!(Config::from_env().is_err());
        });
        with_var("NSNCD_WORKER_COUNT", Some("ten"), || {
            assert!(Config::from_env().is_err());
        });
        with_var(
            "NSNCD_WORKER_COUNT",
            Some("1000000000000000000000000"),
            || {
                assert!(Config::from_env().is_err());
            },
        );
        with_var("NSNCD_WORKER_COUNT", Some(""), || {
            assert!(Config::from_env().is_err());
        });
    }

    #[test]
    fn test_handoff_timeout() {
        with_var_unset("NSNCD_HANDOFF_TIMEOUT", || {
            let config = Config::from_env().unwrap();
            assert_eq!(config.handoff_timeout, Config::default().handoff_timeout);
        });
        with_var("NSNCD_HANDOFF_TIMEOUT", Some("13"), || {
            let config = Config::from_env().unwrap();
            assert_eq!(config.handoff_timeout, Duration::from_secs(13));
        });
        with_var("NSNCD_HANDOFF_TIMEOUT", Some("13s"), || {
            assert!(Config::from_env().is_err());
        });
        with_var("NSNCD_HANDOFF_TIMEOUT", Some("0"), || {
            assert!(Config::from_env().is_err());
        });
        with_var("NSNCD_HANDOFF_TIMEOUT", Some("-1"), || {
            assert!(Config::from_env().is_err());
        });
        with_var("NSNCD_HANDOFF_TIMEOUT", Some("ten"), || {
            assert!(Config::from_env().is_err());
        });
        with_var(
            "NSNCD_HANDOFF_TIMEOUT",
            Some("1000000000000000000000000"),
            || {
                assert!(Config::from_env().is_err());
            },
        );
        with_var("NSNCD_HANDOFF_TIMEOUT", Some(""), || {
            assert!(Config::from_env().is_err());
        });
    }

    #[test]
    fn test_ignore_vars() {
        with_var_unset("NSNCD_IGNORE_INITGROUPS", || {
            let config = Config::from_env().unwrap();
            assert!(!config.ignore_getpwbyname);
            assert!(!config.ignore_initgroups);
        });
        with_var("NSNCD_IGNORE_INITGROUPS", Some("true"), || {
            let config = Config::from_env().unwrap();
            assert!(!config.ignore_getpwbyname);
            assert!(config.ignore_initgroups);
        });
        with_var("NSNCD_IGNORE_INITGROUPS", Some("false"), || {
            let config = Config::from_env().unwrap();
            assert!(!config.ignore_getpwbyname);
            assert!(!config.ignore_initgroups);
        });
        with_var("NSNCD_IGNORE_INITGROUPS", Some("yes"), || {
            assert!(Config::from_env().is_err());
        });
        with_var("NSNCD_IGNORE_INITGROUPS", Some("y"), || {
            assert!(Config::from_env().is_err());
        });
        with_var("NSNCD_IGNORE_INITGROUPS", Some("no"), || {
            assert!(Config::from_env().is_err());
        });
        with_var("NSNCD_IGNORE_INITGROUPS", Some("n"), || {
            assert!(Config::from_env().is_err());
        });
        with_var("NSNCD_IGNORE_INITGROUPS", Some("1"), || {
            assert!(Config::from_env().is_err());
        });
        with_var("NSNCD_IGNORE_INITGROUPS", Some("0"), || {
            assert!(Config::from_env().is_err());
        });
        with_var("NSNCD_IGNORE_INITGROUPS", Some(""), || {
            assert!(Config::from_env().is_err());
        });
        with_vars(
            vec![
                ("NSNCD_IGNORE_GETPWBYNAME", Some("false")),
                ("NSNCD_IGNORE_INITGROUPS", Some("true")),
            ],
            || {
                let config = Config::from_env().unwrap();
                assert!(!config.ignore_getpwbyname);
                assert!(config.ignore_initgroups);
            },
        );
        with_vars(
            vec![
                ("NSNCD_IGNORE_GETPWBYNAME", Some("true")),
                ("NSNCD_IGNORE_INITGROUPS", Some("false")),
            ],
            || {
                let config = Config::from_env().unwrap();
                assert!(config.ignore_getpwbyname);
                assert!(!config.ignore_initgroups);
            },
        );
        with_vars(
            vec![
                ("NSNCD_IGNORE_GETPWBYNAME", Some("true")),
                ("NSNCD_IGNORE_INITGROUPS", Some("true")),
            ],
            || {
                let config = Config::from_env().unwrap();
                assert!(config.ignore_getpwbyname);
                assert!(!config.ignore_getpwbyuid);
                assert!(config.ignore_initgroups);
            },
        );
        with_vars(
            vec![
                ("NSNCD_IGNORE_GETPWBYNAME", Some("1")),
                ("NSNCD_IGNORE_INITGROUPS", Some("true")),
            ],
            || {
                assert!(Config::from_env().is_err());
            },
        );
    }
}
