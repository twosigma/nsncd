# nsncd - the name service non-caching daemon

`nsncd` is a nscd-compatible daemon that proxies lookups, without caching.

## Why?

`nsncd` can be used in situations where you want to make an application use nss
plugins available to a different libc than the one the application will load.
Since most (all?) libc implementations will try to use `/var/run/nscd/socket` if
it exists, you can make all lookups on a machine attempt to use the libc that
nsncd is running with (and any nss plugins available to it), regardless of the
libc used by a particular application.

It is also a fairly minimal and clean implementation of (a part of) the `nscd`
protocol, which is otherwise only really documented in implementations of libc,
and mailing lists.

## Installing

Just run the `nsncd` binary and it will listen at `/var/run/nscd/socket`.
There's a simple `systemd` unit file, too.

If you're on a Debian-based system, you can use the provided Debian package to
install `nsncd` to run under `systemd`. See `debian/README.source` for how to
build it - we use a few Rust crates that aren't packaged for stable Debian
releases.

## Configuration

`nsncd` looks in its environment for configuration.

There are two integer variables we pay attention to: `NSNCD_WORKER_COUNT` and
`NSNCD_HANDOFF_TIMEOUT`. Both must be positive (non-zero), and the timeout is
in seconds.

We also pay attention to variables `NSNCD_IGNORE_<DATABASE>` where `<DATABASE>`
is one of the database names from `nsswitch.conf(5)`, capitalized:

- NSNCD_IGNORE_GROUP
- NSNCD_IGNORE_HOSTS
- NSNCD_IGNORE_INITGROUPS
- NSNCD_IGNORE_NETGROUP
- NSNCD_IGNORE_PASSWD
- NSNCD_IGNORE_SERVICES

These variables must be either `true` or `false`. The default is `false` (don't
ignore any requests). If one of these variables is set to true, `nsncd` will
not respond to the requests related to that database.

Some request types may be ignored by the implementation (e.g. the ones that
request a file descriptor pointing into internal cache structures).

## Bug Reports and Contributions

Please create GitHub issues and/or pull requests.

## License

`nsncd` is licensed under the [Apache License 2.0](./LICENSE).
