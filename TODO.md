- Parse host from requests, serve different roots per host.
  - So, for HTTPS, there's a TLS extension that provides the server name before
    encryption starts, so that the right cert can be chosen.
  - There's a newer version (ESNI) that encrypts the server name to close the
    server name disclosure hole in the original.
  - Should probably use a directory layout for host keys: D/host/{cert,key}

- Customizable xtension to mimetype mapping.
  - Mechanism?

- Unencrypted HTTP handling so I can turn off publicfile.
  - I feel like a simple 301 redirect to HTTPS would suffice.
    - Are there clients that don't use HTTPS still?
  - Looks like 307 with `Non-Authoritative-Reason: HSTS` is the right way.
