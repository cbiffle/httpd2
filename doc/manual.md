# `httpd2` user manual

## Minimum Secure Configuration

This is up front so you don't miss it. To run `httpd2` with all the security
features enabled, you need to do the following:

1. Point it at your server private key (`-k` option) and cert (`-r` option).

2. Pass the `--chroot` / `-c` flag to ask `httpd2` to chroot into the web
   content directory, removing its ability to see other stuff.

3. Pass the `--uid` / `-U` and `--gid` / `-G` flags to ask `httpd2` to switch to
   an unprivileged user account after startup (e.g. `nobody`, or a dedicated
   user).

Security hygiene tips:

- Don't put your private key in the web content directory. That's asking the
  webserver to serve your private key to others, which would make the "private"
  part less meaningful.

- Avoid putting hardlinks from _inside_ your web content directory to other
  places on the system. This could allow a chroot escape. If you do this, be
  careful where you point them.

## Running `httpd2` for development

**Linux:** After checking out the sources (and installing a Rust toolchain,
natch), run:

```shell
cargo run path_to_web_pages
```

...where `path_to_web_pages` is a path (absolute or relative) to a directory of
web pages you would like to serve. This will start the server on port 8000 as an
unprivileged user without chrooting, using a self-signed key.

**Non-Linux Unix-Like Systems and/or Linux distros rebelling against systemd:**
Add `--no-default-features` to disable logging to journald. I would like to make
this automatic but am not entirely sure how. Patches welcome!

**By default, the server is compiled with minimal optimizations,** so this
configuration isn't ideal for load testing. To fix this, add the `--release`
flag to `run`.

## How `httpd2` decides what to serve

### Path normalization

When a request for a given path comes in, `httpd2` ignores the URL part, and
tries to look up the path in the web content directory. But first, it normalizes
the path:

- Paths are forced to be _relative_ (by prepending a `./`').
- Repeated slashes `///` are collapsed to a single slash.
- Any dot after a slash (`/.`) is replaced by a colon (`/:`). This prevents the
  server from following `..` links or serving Unix-style "hidden" files, while
  still letting you serve URLs that _appear_ to contain dots.
- Any NUL (`'\0'`) in the path is replaced by an underscore, because the
  underlying operating system is fundamentally a C program, and NULs in
  filenames are likely to cause it to do weird stuff.

Lookup then proceeds with the normalized path.

### Directory listing (or lack thereof)

If the path winds up resolving to a directory, `httpd2` acts as though the
request had ended in `index.html`, and proceeds with the process below. (It does
_not_ issue an HTTP Redirect to `index.html`, so the browser's URL stays clean.)

### Mode checks

If a file is found, `httpd2` verifies that its mode is at least octal `444` --
that is, it must be user/group/world readable. Otherwise, `httpd2` assumes that
you left a secret file in the web content directory by accident, and _pretends
not to see it._ (If you get in this situation you will see log messages
indicating that the file mode was not OK.)

### Compressed alternative

Just before deciding to serve a file, `httpd2` will check alongside it for a
compressed _version_ of the file. If...

- Next to the file, in the same directory, is a file with the same name plus
  `.gz`...
- That file exists and is readable (per the mode check definition above)...
- The client has expressed interest in a GZIP `Content-Encoding` in the
  response...
- _And_ the `.gz` file has been modified _at or later than_ the time the
  non-`.gz` file was modified

then `httpd2` will serve the contents of the compressed file instead.

This mechanism works the way it does to save CPU by not compressing anything on
the fly. There are a couple of potential drawbacks:

- Technically, you can serve different versions of pages to clients that want
  compressed content vs. uncompressed. I won't stop you, but I will give you
  some side-eye.
- It's possible for the GZIPped version to simply be _stale_ relative to the
  uncompressed version. The last-modified check is an attempt to catch this.
- If a user asks for one of your pages with an explicit `.gz` resource, `httpd2`
  will happily hand them `index.html.gz` (for example) as a GZIP file. This is
  potentially surprising, but likely not a _problem_ per se.

### How to serve weird stuff

`httpd2`'s path normalization might make it look as though you can't serve
certain kinds of URLs, such as those containing `..`. Not so! You just have to
be very explicit about it:

- To serve a file/directory with a leading dot, replace the dot by a colon. So
  the `.well-known` directory used for domain verification by Let's Encrypt, for
  example, becomes `:well-known`.

- To _appear_ to support directory traversal, you can create directories called
  `:.`. This can be useful for honeypotting attempts at directory traversal
  exploits.

- As always, make sure that anything you're trying to serve is world readable.

## Logs

`httpd2` logs to stdout and (on Linux) journald by default, using `slog`. The
log format used is not compatible with other HTTP servers, for better or worse,
though I have designed it to allow easy correlation of messages from multiple
concurrent request threads.
