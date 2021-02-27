# My comparison of `httpd2` with `publicfile`

`httpd2` is my experimental HTTPS 1/2 static file server.

[`publicfile`] is an HTTP1 static file server that inspired `httpd2`.
`publicfile` was written by [`djb`].

## About `publicfile` (for our purposes)

[`publicfile`] is a _pretty good_ example of how to write a secure forking
server on Unix in C. I suggest studying and understanding its source code at
some point. (I used to recommend studying `djb`'s craft more broadly, but his
[prideful handling of a remote code execution vulnerability in
`qmail`][djb-qmail-cve], caused by his own inattention to integer overflows,
has damaged my respect for him.)

`publicfile` does not, itself, speak TCP/IP -- it relies on `ucspi-tcp` to do
the networky bits. This factoring has a lot of advantages and some drawbacks,
but this is not an analysis of `publicfile` itself.

I ran the `publicfile`-`ucspi-tcp` stack for many years, but I eventually ran
into some problems:

1. HTTP support is limited to HTTP/1.1.
2. No TLS support.
3. No IPv6 support.
4. Maximum concurrency is limited by the use of one process per request.
5. No `Content-Encoding` support, so files are not sent compressed.
6. The hardcoded MIME type selection was very mid-90s, and the way to override
   it changes the client-visible file extension, confusing Windows.
7. Fixing any of these things is difficult because of `publicfile`'s license.

On that last one: `publicfile` is not open source in the modern sense of the
word -- its license does not permit distribution of derivative works. I can't
simply fix things and put up a fork on GitHub. People have distributed sets of
patches against the source code for years, including patches that fix a few of
the issues I've listed here, but these patches often conflict with each other,
and the site that used to archive them recently disappeared from the internet,
leaving me unable to rebuild my server binary.

My first Rust project was actually a [clone of `publicfile`][httpd1], so faced
with these issues, I decided to do it again.

## Ways `httpd2` and `publicfile` are similar

- Both programs serve parts of the filesystem to the web, and nothing else.

- Both programs use the same methods for avoiding path traversal, TOCTOU, and
  unwanted file disclosure. Specifically, `httpd2` uses a direct gloss of
  `publicfile`'s path sanitization and mode checking logic and requires that
  files meet the same criteria.

- Both programs `chroot` and drop privileges. (In both programs, the behavior is
  optional and not on by default, meaning both are somewhat insecure in the
  default configuration. I am planning on switching this.)

- Both programs generate error messages that attempt to disclose as little
  information as possible. Any file that can't be served is 404 (not found),
  even if it exists but is privileged, which would be an information-revealing
  403 (forbidden) on most servers. Neither program will deliver a handy stack
  trace or admit an "internal server error" to an attacker.

- There is very little interesting information to try and extract from either
  server. There is no privileged configuration file, no content that requires
  authentication, no database handle, and very little mutable state at all.
  (`httpd2`'s memory image does contain one significant piece of sensitive data:
  its private key. I'll talk more about that in a bit.)

- Neither program will read or parse a configuration file. There are few
  configurable options, and they are all set by command line flags. This means
  no parser codebase to target, and no risk of accidentally leaving the
  configuration file writable by other users.

## Ways `httpd2` is different

### `httpd2` supports the modern web

`publicfile` supports HTTP 0.9 through 1.1, a set of MIME types commonly used on
the academic Internet in the mid-90s, and some useful features like persistent
connections. While it mostly outsources IP to `ucspi-tcp`, it embeds enough
assumptions about IPv4 that it can't support IPv6 without patches.

People who are browsing with IPv4 disabled, or the HTTPS Everywhere extension,
can't access `publicfile` at all. (And apparently those are the sort of people
who read my blog, so I hear about it regularly.)

`httpd2` supports HTTPS 1.1 and 2, pipelined multiplexed request streams, TLS
encryption, and IPv4/6. I have no intent to support unencrypted HTTP, which is
effectively deprecated here in 2020.

`httpd2` still uses a `publicfile`-style hardcoded set of MIME types, but the
set is more appropriate for a static website in 2020. (I plan to make this
configurable, eventually.)

### `httpd2` is an asynchronous, single-process server

`publicfile` is a traditional one-process-per-connection Unix daemon (a "forking
server"). `httpd2` is a single-process multi-threaded asynchronous server. This
means that `httpd2` interacts with clients exclusively using non-blocking
operations, and tracks the state of each connection and request in a data
structure, instead of in the state of a thread of execution. A small pool of
threads serves all outstanding connections.

Pros:

- Because an incoming connection no longer requires a `fork`, and an in-progress
  connection no longer requires a separate process, `httpd2` can handle a lot
  more concurrent connections with a lot fewer resources. For example, if
  permitted by `ulimit` to have enough file descriptors, a single server has no
  problem handling 10,000 concurrent connections on a 2018-vintage laptop.

- Because connections are less costly, the server is less vulnerable to
  SlowLoris-style DoS attacks. (Still vulnerable, but less so.)

- The asynchronous architecture makes implementing HTTP/2 _much easier,_ and
  HTTP/2 gives a better user experience with lower server resources. HTTP/2
  extends the concept of HTTP pipelining by internally multiplexing each
  connection into a number of concurrent request streams. This model means that,
  even if the HTTP/2 server forked one process per connection, each such process
  would still need to keep track of multiple in-flight operations. This means
  you've now got _two_ ways of forking state (`fork` and muxing) and that's one
  too many for me.

As you might expect when comparing software to something from DJB, the "Cons"
are mostly in the security area:

- A `publicfile` process serves a single connection, and is then destroyed --
  whereas `httpd2` serves the entire website with a single process. This means
  that the server has to deal with failure using a tool other than `abort`.
  `publicfile`'s willingness to `abort` means that it rarely has to think about
  things like memory leaks or "unwinding" error conditions correctly. These are
  much harder to do correctly in C than in Rust, and so I am less concerned.

- Because the `httpd2` process serves multiple connections within the same
  address space, it is possible that a bug would allow actions taken on one
  connection to affect another by corrupting or revealing state. I've mitigated
  this by using a memory-safe language and well-tested (and fuzz-tested)
  libraries.

- Similarly, because the server survives across connections, it's possible that
  a bug could deliver a payload into the server address space that would alter
  or disclose future connections. This is mitigated in the same way. (The server
  is also functionally stateless and fast to restart, so [prophylactic
  reboots][candea] are also an option.)

- `httpd2` does not support the UCSPI-TCP interface, and instead needs to bind
  its own socket. This means the server process briefly runs as root before
  dropping privileges. However, so does publicfile (because of the need to
  `chroot`).

### `httpd2` is written in Rust.

I think it's important to neither overstate, nor understate, the importance of
this one.

`publicfile` is written in C (circa the C89 standard).

`httpd2` is written in Rust (2018 edition, if you're curious).

This has some implications for how I approach software engineering problems.

- Buffer overrun, use-after-free, accidental memory leaks, and other memory
  safety errors are much harder to produce. (You have to go out of your way
  using `unsafe`.)

- Integer overflow is trapped, and is thus a thing I don't need to spend time
  thinking about. This gets its own bullet because it's a very common source of
  mistakes in C, [including in DJB's code][djb-qmail-cve]. (I am aware that he
  is continuing to stomp his feet and insist that the users are holding it
  wrong, but the fact remains that that code _could_ have been written correctly
  if he had cared, and would have been written that way _by default_ in Rust.)

- Because the likelihood of state corruption is lower (due to the above
  bullets), I am less wedded to the idea of `abort` on recoverable errors, which
  means I can use a multithreaded instead of multiprocess server.

- The type system protects against data races and unguarded sharing of data
  across threads, so a large class of concurrency bugs are much harder to
  produce -- so I can consider a multithreaded server _without_ reintroducing
  opportunities for state corruption.

- The availability of `async` means that I can write asynchronous, event-driven
  code as straight-line code and let the compiler sort it out. This in turn
  means that I'm willing to use event-driven state machines in contexts where
  writing an explicit state machine by hand would have made the code too
  difficult to audit and reason about.

My use of Rust here has also had some unexpected results (at least, I wasn't
expecting them):

- `httpd2` is less prone to disclosing server crashes in certain contexts,
  because the Rust code is using `Result` error handling and can ensure that any
  surprises result in a `404` response rather than termination of the
  connection. This is good -- I don't want to tell visitors if they have
  successfully tickled a crashing codepath in my server! That information should
  go the logs, only.

- `httpd2` is considerably faster than Publicfile, particularly in high load
  situations. This is not because Rust is faster than C intrinsically -- it is
  because, by freeing my brain from worrying about C problems, I was able to
  build a faster server.

### `httpd2` relies on software written by other people.

`publicfile`, like most of DJB's software from its era, doesn't use third-party
dependencies, and in fact goes to some length to isolate itself from bugs *in
the C library.* I think this is admirable, and I'm not doing it.

`httpd2` relies on Tokio, Hyper, and Rustls, in addition to parts of the Rust
standard library. These libraries are sure to contain bugs, but they are also
mainstays of the Rust community, in production use by a lot of folks, and are
fuzz-tested -- in addition to being written in Rust in the first place.

But the reason I'm willing to do this mostly comes down to Rust's build system.
The version of every library in `httpd2`'s transitive build graph is checked
into this repo in `Cargo.lock`, including the cryptographic hashes of their
source code. I know that you will get the same versions I tested against, and
that will not change until I push an update to `Cargo.lock` (after, presumably,
testing). This is _very much_ not the case in C.

This is not without its drawbacks, of course.

For one, I am exposed to possible vulnerabilities due to bugs in those
libraries, or any supply chain attacks executed before I pinned the dependency
versions. It's theoretically possible that a subtle logic bomb was inserted into
one of the libraries I'm using, just waiting to go off and scramble my address
space. (I'm less concerned about this because the server chroots and drops
privileges before using library code, so the impact of this would be limited to
web traffic.)

Another drawback: the server binary is much, much larger than either
`publicfile` or an unpublished version I wrote myself without using Tokio/Hyper.
Specifically, as of this writing, `httpd2` is 3MiB. My build of `publicfile`,
with patches, is 23kiB. This difference is not fatal: in practice, the working
set of either binary will fit entirely into CPU cache in 2020.

[djb-qmail-cve]: https://www.qualys.com/2020/05/19/cve-2005-1513/remote-code-execution-qmail.txt
[httpd1]: https://github.com/cbiffle/httpd1
[candea]: http://roc.cs.berkeley.edu/talks/Reboot_OSDI2000_WIP.pdf
[`publicfile`]: https://cr.yp.to/publicfile.html
[`djb`]: https://cr.yp.to/
