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

## Bug Reports and Contributions

Please create GitHub issues and/or pull requests.

## License

`nsncd` is licensed under the [Apache License 2.0](./LICENSE).
