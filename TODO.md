- Parse host from requests, serve different roots per host.

- Customizable xtension to mimetype mapping.

- If Modified Since

- Listen on multiple IP/ports (in particular, IPv4 and v6)

- Unencrypted HTTP handling so I can turn off publicfile.
  - I feel like a simple 301 redirect to HTTPS would suffice.
  - Should also implement HSTS to encourage browsers to do the redirect.
