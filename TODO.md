- Parse host from requests, serve different roots per host.

- Customizable xtension to mimetype mapping.

- If Modified Since

- Unencrypted HTTP handling so I can turn off publicfile.
  - I feel like a simple 301 redirect to HTTPS would suffice.
  - Looks like 307 with `Non-Authoritative-Reason: HSTS` is the right way.
