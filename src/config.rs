/*
 * Copyright 2022-2023 Two Sigma Open Source, LLC
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

//! Configuration for nsncd.

use std::time::Duration;
use std::{collections::BTreeMap, env};

use anyhow::{Context, Result};
use num_traits::FromPrimitive;
use static_assertions::const_assert;

use super::protocol::RequestType;

/// Size of the bitset for request types. Smaller values tend to exhibit worse
/// cache performance in some quick benchmarks:
/// https://gist.github.com/blinsay/3d233a09c59c083d8d27ccba4e322f04
const BITSET_SIZE: usize = 256;
const_assert!((RequestType::LASTREQ as usize) < BITSET_SIZE);

#[derive(Clone, Copy)]
pub struct RequestTypeSet {
    bits: [bool; BITSET_SIZE],
}

impl RequestTypeSet {
    pub fn new() -> Self {
        Self {
            bits: [Default::default(); BITSET_SIZE],
        }
    }

    pub fn insert(&mut self, val: &RequestType) -> bool {
        let val = *val as usize;
        if self.bits[val] {
            false
        } else {
            self.bits[val] = true;
            true
        }
    }

    pub fn contains(&self, val: &RequestType) -> bool {
        let val = *val as usize;
        self.bits[val]
    }
}

impl Default for RequestTypeSet {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for RequestTypeSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut f = f.debug_set();
        for i in 0..(RequestType::LASTREQ as i32) {
            let ty = &FromPrimitive::from_i32(i).unwrap();
            if self.contains(ty) {
                f.entry(ty);
            }
        }
        f.finish()
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Config {
    pub ignored_request_types: RequestTypeSet,
    pub worker_count: usize,
    pub handoff_timeout: Duration,
}

/// Mapping from nsswitch.conf "database" name to the request types related to
/// that database.
const OPS_BY_DATABASE: &[(&str, &[RequestType])] = &[
    (
        "group",
        &[RequestType::GETGRBYNAME, RequestType::GETGRBYGID],
    ),
    (
        "hosts",
        &[
            RequestType::GETHOSTBYADDR,
            RequestType::GETHOSTBYADDRv6,
            RequestType::GETHOSTBYNAME,
            RequestType::GETHOSTBYNAMEv6,
            RequestType::GETAI,
        ],
    ),
    ("initgroups", &[RequestType::INITGROUPS]),
    (
        "netgroup",
        &[RequestType::GETNETGRENT, RequestType::INNETGR],
    ),
    (
        "passwd",
        &[RequestType::GETPWBYNAME, RequestType::GETPWBYUID],
    ),
    (
        "services",
        &[RequestType::GETSERVBYNAME, RequestType::GETSERVBYPORT],
    ),
];

impl Config {
    /// Parse config out of the environment.
    ///
    /// There are two integer variables we pay attention to:
    /// `NSNCD_WORKER_COUNT` and `NSNCD_HANDOFF_TIMEOUT`. Both must be positive
    /// (non-zero).
    ///
    /// We also pay attention to variables `NSNCD_IGNORE_<DATABASE>` where
    /// `<DATABASE>` is one of the database names from `nsswitch.conf(5)`,
    /// capitalized:
    ///
    /// - NSNCD_IGNORE_GROUP
    /// - NSNCD_IGNORE_HOSTS
    /// - NSNCD_IGNORE_INITGROUPS
    /// - NSNCD_IGNORE_NETGROUP
    /// - NSNCD_IGNORE_PASSWD
    /// - NSNCD_IGNORE_SERVICES
    ///
    /// These variables must be either `true` or `false`. The default is
    /// `false` (don't ignore any requests). If one of these variables is set
    /// to true, `nsncd` will not respond to the requests related to that
    /// database.
    ///
    /// Some request types may be ignored by the implementation (e.g. the ones
    /// that request a file descriptor pointing into internal cache
    /// structures).
    pub fn from_env() -> Result<Self> {
        let ops_map = {
            let mut ops_map = BTreeMap::new();
            for (op_group, types) in OPS_BY_DATABASE.iter() {
                ops_map.insert(op_group.to_uppercase().into_boxed_str(), *types);
            }
            ops_map
        };

        let mut ignored_request_types = RequestTypeSet::new();

        for (key, value) in env::vars() {
            if let Some(op_group) = key.strip_prefix("NSNCD_IGNORE_") {
                let types = ops_map.get(op_group).ok_or_else(|| {
                    let groups = ops_map.keys().map(|s| &**s).collect::<Vec<_>>().join(", ");
                    anyhow::format_err!("Unknown group '{}'. Choose from: {}", op_group, groups)
                })?;
                let value = value
                    .parse()
                    .with_context(|| format!("parsing bool from {}", value))?;
                if value {
                    for ty in types.iter() {
                        ignored_request_types.insert(ty);
                    }
                }
            }
        }

        Ok(Self {
            ignored_request_types,
            worker_count: env_positive_usize("NSNCD_WORKER_COUNT", 8)?,
            handoff_timeout: Duration::from_secs(
                env_positive_usize("NSNCD_HANDOFF_TIMEOUT", 3)? as u64
            ),
        })
    }

    pub fn should_ignore(&self, ty: &RequestType) -> bool {
        self.ignored_request_types.contains(ty)
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            worker_count: 8,
            handoff_timeout: Duration::from_secs(3),
            ignored_request_types: Default::default(),
        }
    }
}

fn env_positive_usize(var: &str, default: usize) -> Result<usize> {
    let s = match env::var(var) {
        Ok(s) => s,
        Err(_) => return Ok(default),
    };
    let val = s
        .parse()
        .with_context(|| format!("parsing int from {}", s))?;
    if val > 0 {
        Ok(val)
    } else {
        Err(anyhow::format_err!("variable {} cannot be 0", var))
    }
}

#[cfg(test)]
mod test {
    use std::time::Duration;

    use temp_env::{with_var, with_var_unset, with_vars};

    use super::Config;
    use super::RequestType;

    #[test]
    fn test_defaults() {
        let config = Config::default();
        assert_eq!(config.worker_count, 8);
        assert_eq!(config.handoff_timeout, Duration::from_secs(3));
        assert!(!config.should_ignore(&RequestType::GETPWBYNAME));
        assert!(!config.should_ignore(&RequestType::GETPWBYUID));
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
            assert!(!config.should_ignore(&RequestType::GETPWBYNAME));
            assert!(!config.should_ignore(&RequestType::INITGROUPS));
        });
        with_var("NSNCD_IGNORE_INITGROUPS", Some("true"), || {
            let config = Config::from_env().unwrap();
            assert!(!config.should_ignore(&RequestType::GETPWBYNAME));
            assert!(config.should_ignore(&RequestType::INITGROUPS));
        });
        with_var("NSNCD_IGNORE_INITGROUPS", Some("false"), || {
            let config = Config::from_env().unwrap();
            assert!(!config.should_ignore(&RequestType::GETPWBYNAME));
            assert!(!config.should_ignore(&RequestType::INITGROUPS));
        });

        // Invalid values
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

        // Invalid keys
        with_var("NSNCD_IGNORE_initgroups", Some("true"), || {
            assert!(Config::from_env().is_err());
        });
        with_var("NSNCD_IGNORE_ZZZNOTAGROUP", Some("true"), || {
            assert!(Config::from_env().is_err());
        });

        // Some combinations
        with_vars(
            vec![
                ("NSNCD_IGNORE_PASSWD", Some("false")),
                ("NSNCD_IGNORE_INITGROUPS", Some("true")),
            ],
            || {
                let config = Config::from_env().unwrap();
                assert!(!config.should_ignore(&RequestType::GETPWBYNAME));
                assert!(config.should_ignore(&RequestType::INITGROUPS));
            },
        );
        with_vars(
            vec![
                ("NSNCD_IGNORE_PASSWD", Some("true")),
                ("NSNCD_IGNORE_INITGROUPS", Some("false")),
            ],
            || {
                let config = Config::from_env().unwrap();
                assert!(config.should_ignore(&RequestType::GETPWBYNAME));
                assert!(!config.should_ignore(&RequestType::INITGROUPS));
            },
        );
        with_vars(
            vec![
                ("NSNCD_IGNORE_PASSWD", Some("true")),
                ("NSNCD_IGNORE_INITGROUPS", Some("true")),
            ],
            || {
                let config = Config::from_env().unwrap();
                assert!(config.should_ignore(&RequestType::GETPWBYNAME));
                assert!(config.should_ignore(&RequestType::GETPWBYUID));
                assert!(!config.should_ignore(&RequestType::GETGRBYGID));
                assert!(config.should_ignore(&RequestType::INITGROUPS));
            },
        );
        with_vars(
            vec![
                ("NSNCD_IGNORE_PASSWD", Some("1")),
                ("NSNCD_IGNORE_INITGROUPS", Some("true")),
            ],
            || {
                assert!(Config::from_env().is_err());
            },
        );
        with_vars(
            vec![
                ("NSNCD_IGNORE_PASSWD", Some("true")),
                ("NSNCD_IGNORE_ZZZNOTAGROUP", Some("true")),
            ],
            || {
                assert!(Config::from_env().is_err());
            },
        );
    }
}
