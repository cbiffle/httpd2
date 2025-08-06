# `httpd2` user manual

**IMPORTANT:** Read the section below titled _Minimum Secure Configuration_
before running `httpd2` on the open internet. It is possible to configure
`httpd2` in an insecure mode if you don't do this.

## Intro

`httpd2` is a _static file webserver._ It accepts requests from other computers
on the internet, checks to see if they match a file it's been asked to serve,
and if so send the file in response.

At a high level, that's the whole story, but of course the devil's in the
details.

I designed `httpd2` to behave differently from most other webservers. It's
intended to serve websites -- mostly, small websites -- very quickly, with
minimal load on the server and minimal extra work for clients. I also designed
it to be resistant to most known classes of attacks on webservers these days.

`httpd2` is what you might call an _opinionated_ webserver. It does things one
way and generally resists being configurable, except in small cases. This is to
ensure that there aren't lesser-used paths through the code sitting there
untested and rotting. I've tried to make its way of doing things pretty general,
so you can probably use it to serve an existing static-file website without
modifying it. That being said, like any opinionated thing, `httpd2` is probably
not for everyone, and that's okay.

## Ways `httpd2` is opinionated, and the reasons why

You'll want to be cool with these opinions before using `httpd2` or the
experience will be frustrating:

- Static sites only. `httpd2` reads files from disk and sends them to the
  network. That's it. It won't run a PHP script, it won't connect to a database.
  It won't even compress or decompress anything (though it supports all modern
  compression methods using pre-compressed files).
  - This eliminates a large class of potential remote attacks that rely on code
    execution or generating large amounts of load.
  - This also keeps server load as low as possible, ensuring that the site
    scales well and is inexpensive to operate.
  - This includes generating directory listings -- `httpd2` doesn't know how to
    do that, which prevents attackers from being able to snoop around for files.
  - You can always run a second dynamic webserver on a separate port or domain
    if you need to.

- No secrets other than the private key. Anything in the web content directory
  is liable to be served to anyone on the internet. There is no authentication
  and no notion of privileged vs. unprivileged users.
  - This ensures there is no authentication mechanism to attack.
  - There are some defenses built in against serving content that is
    _unintentionally_ included in the web content directory, such as dotfiles
    like `.git`. More details on that below.

- HTTPS (HTTP over TLS) only. No unencrypted service, and no _effectively_
  unencrypted service (TLS 1.1, weak ciphers).
  - Getting a high-quality certificate is now free, so there's no reason not to
    do it.
  - HTTP-only (unencrypted) sites are increasingly ignored by search engines and
    other tools.
  - HTTP/2 greatly improves the user experience while reducing server load, and
    is only available over TLS.
  - You might not feel like your site contains anything important enough to
    encrypt, but your users might feel differently depending on the laws in
    their jurisdiction -- plus, TLS prevents spoofing and meddling-in-the-middle
    attacks.

- Disclose as little information as possible to remote users. Even a server
  panic is returned as a 404 rather than a 500 Internal Server Error. In
  particular, never send a stack trace to an untrusted party!
  - This makes it difficult to probe the server for crashes and potentially
    exploitable issues.
  - This doesn't meaningfully affect the end-user experience, where an error is
    an error.
  - Actual errors are recorded in the logs for your reference, since (I assume!)
    you trust yourself to see them.
  - `httpd2` also does not identify itself with an HTTP `server:` header.

- Supplement the other security mitigations by relying on Rust.
  - Bounds-based attacks such as stack smashing and buffer overruns are
    significantly less likely.
  - Each additional connection is very cheap thanks to `async` and tight control
    over memory allocation.
  - Responses are reliably fast and not subject to garbage collection pauses.

## How you use `httpd2` at a high level

Put your website in a directory on your server's filesystem. It should be HTML
and similar things -- it cannot be PHP or Markdown or anything that would
require transformation before it can be served to clients. Static site
generators like Jekyll or Zola or others make this straightforward, but if you
want an active website with a database, `httpd2` is not for you.

Point `httpd2` at that directory. It will serve requests from files in that
directory, and try really hard not to accidentally serve requests for files
_outside_ that directory, like your server's password database.

Before attempting this on a public server, please read the _Minimum Secure
Configuration_ section below.


## What `httpd2` does, specifically

It's worth understanding what this program actually does, so, here's a
walkthrough. It's a bit security-oriented, because I'm a bit security-oriented.

### Startup

`httpd2` starts up by:

1. Parsing command line arguments.
2. Loading its identity (private key and certificate chain) for TLS from disk.
3. Binding its service port (generally 443).
4. Performing a `chroot` into its content directory.
4. Dropping privileges (changing to a different Unix user and group).

`chroot` and dropping privileges are mitigations for potential bugs within
`httpd2` that might allow an attacker to attempt arbitrary filesystem access or
other system calls. The `chroot` ensures that files outside of the web content
directory can't be accessed, even if a bug in `httpd2` let an attacker try it.
Dropping privileges prevents e.g. a remote code execution bug from doing root
things on your server.

Notice that, at this point, `httpd2` has not read any traffic from the network,
nor has it loaded any files from your website. This is deliberate. Reading
traffic from the network allows attacks, and we want attacks to occur once we're
safely sandboxed.

### Connection handling

Now that that's out of the way, `httpd2` handles incoming connections, by

1. Accepting an incoming connection (up to a concurrent connection limit you
   specify).
2. Attempting a TLS handshake using a somewhat narrow set of permitted options
   (TLS 1.2 and later, using a suite of non-crappy ciphers).
3. Reading an HTTP request from the connection.
4. Checking whether the path in the request matches a file that can be served
   (details below).
5. If so, sending the contents of the file.
6. Repeat.

This is a little simplified -- in particular, `httpd2` can concurrently handle
many requests on a single connection. But that's not important for our purposes
here.

How does `httpd2` decide whether a file can be served? Through a two step
process, detailed below.

### Path sanitization

The first step is _sanitization._ Sanitizing a path involves rewriting it into a
canonical form. This doesn't involve any filesystem accesses! The path is
rewritten in memory according to the following rules:

- Paths are required to be in 7-bit ASCII. Other bytes should be
  percent-encoded. This avoids fun behavior in server locale settings.
- Paths are forced to be _relative_ by ensuring they start with `./`, prepending
  either or both characters if necessary.
- Repeated slashes (like `///`) are collapsed into a single slash (`/`).
- A dot after a slash (`/.`) becomes a colon (`/:`) to prevent accidental
  serving of dotfiles and directory traversal, while still letting you serve
  files that _appear_ to start with a dot. More on this below.
- A NUL character is replaced by an underscore (`_`). NUL characters don't
  generally bother Rust code but definitely _do_ bother Unix system calls, so we
  eliminate them.

As a result of this, `httpd2` won't perform path traversal: if you attempt to
load `/foo/../bar`, the path does not get translated into `/bar`. Instead,
`httpd2` translates it to `/foo/:./bar` and serves the request only if a `:.`
directory exists. This prevents serving of dotfiles and traversal in the general
case, while allowing you to deliverately serve dot-names like `.well-known` by
creating the directory with the name `:well-known`.

### Picky file opening

After sanitization we come to the second step in the process, _picky open._ The
picky open algorithm is designed to avoid serving any resource that is
_accidentally_ reachable from the web content directory.

It is at this point that `httpd2` starts making filesystem accesses.

- If the path refers to a directory, we rewrite it to refer to `index.html`
  within that directory and then proceed with the rest of the checks. (This
  only happens once.)
- If it refers to a file, the file must meet the following requirements:
    1. It must be accessible to the user `httpd2` is running as, clearly.
    2. It must be world, group, and user readable (Unix mode 0o444 or better).
    3. If the file is world-executable, it must also be user-executable.
    4. It must be a regular file (not a pipe or device or directory).

File metadata operations use the system calls that operate on open file
descriptors (e.g. `fstat` instead of `stat`) to avoid TOCTOU vulnerabilities in
the algorithm.

### Encoded alternates

Once the process above completes successfully, `httpd2` performs a final check
for an _encoded alternate_ of the file:
- It checks the request's `accept-encoding` HTTP header to see if `gzip` is an
  option.
- If so, it appends `.gz` to the path in your web content directory and performs
  the picky open process again.
- If it succeeds, `httpd2` checks that the `.gz` alternate was last modified _at
  the same time or later than_ the base file, to try to avoid confusing stale
  compressed files.
- If it succeeds, the contents of the `.gz` file are sent with
  `content-encoding: gzip`.
- If any of that fails, or if the user didn't specify `accept-encoding: gzip`,
  the contents of the original file are sent without a `content-encoding`.

This is designed to let you gzip-compress files that benefit from it ahead of
time, and then serve them to clients without needing to compress or decompress
on the fly.


## Minimum Secure Configuration

To run `httpd2` with all the security features enabled, you need to do the
following:

1. Point it at your server private key (`-k` option) and cert (`-r` option).

2. Pass the `--chroot` / `-c` flag to ask `httpd2` to chroot into the web
   content directory, removing its ability to see other stuff.

3. Pass the `--uid` / `-U` and `--gid` / `-G` flags to ask `httpd2` to switch to
   an unprivileged user account after startup (e.g. `nobody`, or a dedicated
   user).

An example minimal secure configuration for `httpd2` might be:

```
httpd2 -c -U 65534 -G 65534 \
    -k /etc/letsencrypt/config/live/yoursite.com/privkey.pem \
    -r /etc/letsencrypt/config/live/yoursite.com/fullchain.pem \
    /your/site/content/directory
```

Security hygiene tips:

- Don't put your private key in the web content directory. That's asking the
  webserver to serve your private key to others, which would make the "private"
  part less meaningful. Ideally, put it in a directory that isn't even
  accessible to the user ID the server uses after startup (here, 65534).

- Avoid putting hardlinks from _inside_ your web content directory to other
  places on the system. This could allow a chroot escape. If you do this, be
  careful where you point them.

## Running `httpd2` for development

`httpd2` requires a Unix-like system, because its security model depends on Unix
features.

After checking out the sources (and installing a Rust toolchain, natch), run:

```shell
cargo run path_to_web_pages
```

...where `path_to_web_pages` is a path (absolute or relative) to a directory of
web pages you would like to serve. This will start the server on port 8000 as an
unprivileged user without chrooting, using a self-signed key.

Note that Linux users can also enable structured logging to journald by adding
`--features journald`.

**By default, the server is compiled with minimal optimizations,** so this
configuration isn't ideal for load testing. To fix this, add the `--release`
flag to `run`.

## Logs

`httpd2` uses an event-oriented structured log format that is, for better or
worse, different from other HTTP servers. It's designed to allow you to inspect
server activity, even for connections that are still outstanding, and to
accurately represent complex multiplexed or pipelined request chains happening
in parallel across many connections.

By default, logs are sent to `stderr`. If you set up `httpd2` to run as a
service under `systemd` on Linux, that will be routed to `journald`
automatically. (On other systems, you can do something similar.) Note that if
your log handler (e.g. `journald` or `syslog`) prepends timestamps to received
log lines, you might want to add the `--suppress-log-timestamps` command line
argument to `httpd2` or you'll get the timestamps twice.

On Linux specifically, `httpd2` can also send logs to `journald` directly, by
enabling the `--features journald` build option, and then specifying `--log
journald` at the command line.

Here is an example log snippet for explanatory purposes. I have wrapped the
lines for clarity in the web browser; they do not wrap in reality to make it
easier to process the logs.

```
Jan 14 19:02:09 : INFO connect, cid: 23938, peer: [REDACTED]:15741
Jan 14 19:02:09 : INFO tls-init, cid: 23938, alpn: h2, tls: TLSv1_3, \
      cipher: TLS13_AES_128_GCM_SHA256
Jan 14 19:02:09 : INFO GET, cid: 23938, rid: 0, \
      uri: https://cliffle.com/blog/making-website-faster/, version: HTTP/2.0, \
      referrer: "https://lobste.rs/"
Jan 14 19:02:09 : INFO response, cid: 23938, rid: 0, status: 200, len: 13661, \
      enc: gzip
Jan 14 19:02:09 : INFO GET, cid: 23938, rid: 1, \
      uri: https://cliffle.com/main.css, version: HTTP/2.0, \
      referrer: "https://cliffle.com/blog/making-website-faster/"
Jan 14 19:02:09 : INFO GET, cid: 23938, rid: 2, \
      uri: https://cliffle.com/blog/making-website-faster/timeline-before.png, \
      version: HTTP/2.0, \
      referrer: "https://cliffle.com/blog/making-website-faster/"
Jan 14 19:02:09 : INFO response, cid: 23938, rid: 1, status: 200, len: 2791, \
      enc: gzip
Jan 14 19:02:09 : INFO response, cid: 23938, rid: 2, status: 200, len: 32043, \
      enc: gzip
Jan 14 19:02:10 : INFO closed, cid: 23937
Jan 14 19:02:10 : INFO GET, cid: 23938, rid: 3, \
      uri: https://cliffle.com/blog/making-website-faster/timeline-after.png, \
      version: HTTP/2.0, \
      referrer: "https://cliffle.com/blog/making-website-faster/"
Jan 14 19:02:10 : INFO response, cid: 23938, rid: 3, status: 200, len: 25263, \
      enc: gzip
Jan 14 19:05:10 : INFO closed, cid: 23938, cause: timeout
```

From top to bottom:

- Every incoming connection, whether TLS negotiation succeeds or not, generates
  a `connect` event. `connect` events have two attributes: `cid` gives a unique
  ID to the connection so you can follow it across log events, and `peer` names
  the address and port where the connection came from.

- The `tls-init` event indicates that TLS negotiation succeeded on the
  connection that was previously announced with the same `cid` (here, 23938). It
  includes a lot of metadata by default: `alpn` here shows that it's an
  HTTP/2-aware client requesting a protocol upgrade; `tls` shows that they're
  using TLS version 1.3; and `cipher` indicates the cipher they've agreed to.

- `GET` events indicate that the server has received a request for a resource on
  an existing connection (23938). `rid` assigns that request a unique ID within
  the connection, so we can follow it; request IDs are always assigned starting
  from 0. The `uri` attribute tells us what the user requested, `version` gives
  the protocol version they're using (which can vary for each request!), and
  `referrer` is the contents of the HTTP referer header (an optional feature
  which can be turned on by adding `--log-referer`).

- The following `response` event indicates that the server is responding to
  `cid: 23938, rid: 0` with an HTTP status 200, which means "OK," so we've
  decided to serve a file. `len` gives the length of the response we're sending
  (13661 bytes), while `enc: gzip` indicates that we found a gzipped alternate
  and the client is okay with that.

- The extra `GET` and `response` events after that follow the same pattern, but
  notice that they're starting to interleave: we get two `GET` events before
  either of them gets a `response`. This is typical on a pipelined or
  multiplexed connection, and being able to track these events accurately in
  time is part of the motivation for this log format.

- The `closed` event we see first is actually for a _different_ connection that
  someone had left open: `cid: 23937`. I included this as a reminder that the
  log stream is multiplexed across all open connections.

- Finally we see our `cid: 23938` close at the very end ... three minutes later
  due to `timeout`. This is because `httpd2` is running with is default
  connection timeout of 181 seconds; you can override this with the
  `--connection-time-limit` flag.

## Configuring httpd2 to run under systemd

Here's how I configured `httpd2` to run on my Linux server. `httpd2` doesn't
require (or even particularly know about) systemd, so it should also work fine
using some other approach. I just happen to like systemd.

First, create a service file. In my case this went into
`/etc/systemd/system/httpd2.service`, because it's a system-local service not
managed by the distro (so it doesn't belong in `/usr`). My service file reads:

```
[Unit]
Description=httpd2
After=network.target

[Service]
EnvironmentFile=-/etc/default/httpd2
ExecStart=/usr/local/bin/httpd2 $HTTPD2_OPTS
KillMode=process
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

Notice that I've punted configuration to an environment file. This will also let
me expand `httpd2` to allow more configuration options in the environment down
the road. For now, though, it mostly keeps all the command line noise out of the
service file. My environment file lives at `/etc/default/httpd2` and reads:

```
# Default settings for httpd2.

# Options to pass to httpd2
HTTPD2_OPTS=\
  -k /etc/letsencrypt/config/live/cliffle.com/privkey.pem \
  -r /etc/letsencrypt/config/live/cliffle.com/fullchain.pem \
  -c -U 65534 -G 65534 \
  \
  -A [::]:443 \
  \
  --upgrade \
  --log-user-agent \
  --log-referer \
  --suppress-log-timestamps \
  --max-threads=10 \
  \
  /public/file/0
```

From top to bottom, we have:

- The `-k` and `-r` options naming the private key and cert chain, respectively
- The `-c`, `-U`, and `-G` options requesting a chroot and switch to the
  `nobody` user (which on my system is numerically 65534).
- An explicit request to bind to `[::]:443`, which forces IPv6.
- `--upgrade` sends the `upgrade-insecure-requests` HTTP header, requesting that
  browsers not follow unencrypted `http:` links to my site.
- `--log-user-agent` adds the HTTP `user-agent` to the logs, which has become
  necessary to identify some attacks recently.
- `--log-referer` adds the HTTP `referer` to the logs, which is far less useful
  than I'd hoped because a lot of programs don't seem to send it anymore.
- `--suppress-log-timestamps` keeps me from getting a double-timestamp in
  journald.
- `--max-threads=10` limits the threadpool to 10, which is higher than my number
  of CPUs, but since `httpd2` primarily uses threads to execute Unix blocking
  filesystem operations, this doesn't cause CPU contention.
- `/public/file/0` is, for historical reasons, where my web content lives.


## Adding MIME types (`Content-Type`)

By default, `httpd2` contains a hardcoded mapping from file extension to MIME
type. (It's in the `serve::default_content_type_map` function if you're
curious.) This contains mappings for several file types that are common on the
modern web, but may be missing mappings that you need.

On startup, `httpd2` scans its environment variables for any variable whose name
starts with `CT_` (case sensitive). It then attempts to process those variables
as additional content-type mappings, as follows:

1. The initial `CT_` is removed.
2. The rest of the name of the environment variable is taken as a file
   extension.
3. The value of the variable is taken as the `Content-Type` to serve when a file
   has that extension, overriding the default if necessary.

As an example, you could re-create the default mapping for files with the
extension `jpg` by setting an environment variable:

```
CT_jpg=image/jpeg
```

(You don't need to set that one, since it's bundled.)

You could also make your webserver behave strangely by setting
`CT_jpg=text/plain`, which would override the default and tell clients that all
your JPEG images are actually just text. But you probably shouldn't.

Providing your `httpd2` server process with a custom environment depends on how
you run the process. If you're running from `systemd` (which is what I do) you
can simply add the mapping to your `EnvironmentFile` specified in your unit
declaration (so using the example declaration from the previous section,
`/etc/default/httpd2`).

If you're running the server from the command line for development, or from a
shell script, you can either `export` the environment variables before running
the server, or prefix them to the command line, e.g.

```
CT_jpg=image/jpeg /usr/local/bin/httpd2 --your-arguments-here
```
