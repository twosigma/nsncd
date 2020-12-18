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

You can use the provided debian package to install `nsncd` to run under
`systemd`. It currently only works when managed by `systemd`, if you're
interested in managing it in other ways, we'd need to modify how process startup
works.

## Bug Reports and Contributions

Please create GitHub issues and/or pull requests.

## License

`nsncd` is licensed under the [Apache License 2.0](./LICENSE).