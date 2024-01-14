# A modern static file server

`httpd2` (working title, as it's the second one I've written recently) is a
program that serves web pages / resources to the public. And that's it. For more
details see [the manual](doc/manual.md).

It is inspired by, and patterned after, [`publicfile`], the security-conscious
static file server &mdash; except it is HTTPS-native and supports HTTP/2. (I
have a [detailed analysis vs.  publicfile](doc/vs.md) if you're into that sort
of thing.)

## Disclaimer

I make no claims that this software is secure or impervious. I wrote this as an
exercise in applying secure programming principles to a modern HTTP server.

## Features

Basics:

- Serves the contents of a single directory as a public website.

- Supports modern web standards: HTTP/1.1, HTTP/2, TLS v1.3, etc.

- Supports GZIP content encoding to reduce bandwidth and improve latency, using
  _precompressed_ files to reduce server load.

- Scales fairly well. (Tested with 10,000+ concurrent connections using multiple
  pipelined requests each.)

Architecture and resource usage:

- Fully asynchronous architecture means it can handle a large number of
  simultaneous connections (10,000+) for not a lot of resources.

- SMP-aware: requests are distributed over threads, and throughput increases as
  cores are added.

- Allocates memory in proportion to the number of simultaneous outstanding
  requests, not the size of any files on disk.

Security practices:

- Before so much as reading from its socket, `httpd2` chroots into the content
  directory and drops privileges. This makes it less likely to provide
  root-level exploits, disclose files outside the content directory like
  `/etc/passwd`, or run system binaries.

- Because the server is designed to serve files that are "public," meaning they
  are handed to any web user, there is no user/password database or admin
  interface to probe or expose.

- `httpd2` can't list directory contents. Navigating to a directory serves an
  `index.html` file if available, and that's it.

- `httpd2` declines all the HTTP state modification commands &mdash; it only
  honors GET and HEAD.

- `httpd2` never runs another program, including script files (there is no CGI
  etc. support).

- `httpd2` ignores files that are not user+group+world readable on the local
  filesystem, so even if you accidentally copy a sensitive file into the web
  root, it's unlikely to be served.

- `httpd2` is written in Rust. Compared to C, this means that certain kind of
  exploits are much less likely (particularly buffer overruns, use-after-free,
  and [integer overflow][djb-qmail-cve]). Compared to other memory-safe
  languages, certain kinds of availability problems are much less likely (such
  as memory leaks, latency stutter, and the like).

- `httpd2` uses pinned versions of well-tested libraries, which are statically
  linked into the binary, rather than loading whatever version happens to be
  installed at startup. (You can build it against MUSL to get a really-really
  static binary.)

## Getting started

Pick a directory containing some world-readable files. (No, really, they must be
mode `0444` or higher.) Let's call that directory `your_dir_here`.

After checking out the server source code, run:

```shell
$ cargo run your_dir_here
```

You should now have an HTTPS server running on `https://localhost:8000/` using a
self-signed certificate. Your browser will freak out the first time you try to
visit it, because the certificate is self-signed. In an actual deployment you'd
use an actual certificate. A reasonable configuration for that might be (note
that you'd have to run this as `root`):

```shell
# httpd2 -k /etc/letsencrypt/privkey.pem \
         -r /etc/letsencrypt/fullchain.pem \
         --chroot \
         --uid 65534 --gid 65534 \
         -A [::]:443 \
         --upgrade \
         /public/file/0
```

This will...

- Use a particular key and cert.
- Chroot into the content directory. (This is currently optional because it
  requires root privileges.)
- `setuid`/`setgid` to the given numeric IDs.
- Bind to all interfaces' IPv6/IPv4 addresses on port 443.
- Send the `upgrade-insecure-requests` directive, which tells clients that find
  an `http:` link within our site to try `https:` instead because our CMS is
  old.
- Serve files found in `/public/file/0`.

## MUSL

If you'd like to produce a fully static program without _any_ system
dependencies on Linux (not even glibc), the current incantation for building
with MUSL on AMD64 is:

```shell
$ cargo build --release --target=x86_64-unknown-linux-musl
```

Or with journald support:

```shell
$ PKG_CONFIG_ALLOW_CROSS=1 cargo build --release --features journald --target=x86_64-unknown-linux-musl
```

## More docs

- [Manual](doc/manual.md)
- [My analysis of this program vs `publicfile`.](doc/vs.md)

[`publicfile`]: https://cr.yp.to/publicfile.html
[djb-qmail-cve]: https://www.qualys.com/2020/05/19/cve-2005-1513/remote-code-execution-qmail.txt
