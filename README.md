# acme-proxy-exec

ACMEProxy-compatible HTTP server that runs shell scripts for DNS-01 `present` / `cleanup`. Use it with [caddy-dns/acmeproxy](https://github.com/caddy-dns/acmeproxy), [acme.sh](https://github.com/acmesh-official/acme.sh) `dns_acmeproxy`, or lego `httpreq` when your DNS (for example djbdns/tinydns) has no native ACME plugin.

Clients authenticate with HTTP Basic Auth. Each user is limited to configured domain suffixes. Credentials live in a YAML config file; there is no remote admin UI.

## Build

```bash
go build -o acme-proxy-exec ./cmd/acme-proxy-exec
```

## Config

Copy [`acmeproxy.example.yaml`](acmeproxy.example.yaml) to `acmeproxy.yaml`, set absolute script paths, and add users:

```bash
chmod 0600 acmeproxy.yaml
./acme-proxy-exec hash-password          # paste hash into users[].password_hash
# or:
./acme-proxy-exec add-user -config acmeproxy.yaml -user bob -domain bob.example.com
```

`add-user` prompts for a password, bcrypt-hashes it, and merges the user/domains into the YAML (read-modify-write; avoid concurrent edits).

Send `SIGHUP` to reload users and script paths without dropping the listener.

### Domain allowlist

Yes — subdomains are allowed. A challenge FQDN matches if it equals an allowlisted domain **or** is any subdomain of it (trailing dots ignored).

If a user has `example.com`, then all of these are allowed:

- `example.com`
- `www.example.com`
- `mail.example.com`
- `_acme-challenge.example.com`
- `_acme-challenge.www.example.com`

`notexample.com` is **not** allowed. To restrict a user to one host only, list that host (e.g. `www.example.com`) instead of the parent zone.

## Scripts

Configured as absolute paths and invoked without a shell:

```text
present <fqdn> <value>
cleanup <fqdn> <value>
```

Exit `0` means success; anything else returns HTTP 500 to the client. Stdout/stderr are logged by the server.

See [`examples/djbdns/`](examples/djbdns/) for POSIX ash (`#!/bin/sh`) stub present/cleanup scripts you can adapt for tinydns.

## Run

```bash
./acme-proxy-exec serve -config acmeproxy.yaml
```

Or set `ACMEPROXY_CONFIG`. Intended for internal/LAN use (same guidance as other ACMEProxy servers). Optional `tls.cert` / `tls.key` in the config terminate TLS on the proxy itself.

Sample supervised / init scripts (adjust paths and the `acmeproxy` user):

- [`examples/daemontools/run`](examples/daemontools/run) — daemontools / runit / s6 `run`
- [`examples/rc.d/acme_proxy_exec`](examples/rc.d/acme_proxy_exec) — FreeBSD `/usr/local/etc/rc.d`
- [`examples/systemd/acme-proxy-exec.service`](examples/systemd/acme-proxy-exec.service) — Linux systemd unit

## Caddy

```
tls {
  dns acmeproxy https://acmeproxy.internal:9090 {
    username bob
    password ...
  }
}
```

## acme.sh

```bash
ACMEPROXY_ENDPOINT="https://acmeproxy.internal:9090" \
ACMEPROXY_USERNAME="bob" ACMEPROXY_PASSWORD="..." \
acme.sh --issue --dns dns_acmeproxy -d bob.example.com
```

## API

| Method | Path       | Body                                      |
|--------|------------|-------------------------------------------|
| POST   | `/present` | `{"fqdn":"_acme-challenge.example.com.","value":"..."}` |
| POST   | `/cleanup` | same                                      |

Basic Auth required. Success: `200` with JSON echoing `fqdn` and `value`.

### curl examples

```sh
curl -sS -u 'bob:secret' \
  -H 'Content-Type: application/json' -H 'Accept: application/json' \
  -d '{"fqdn":"_acme-challenge.www.example.com.","value":"challenge-token"}' \
  http://127.0.0.1:9090/present

curl -sS -u 'bob:secret' \
  -H 'Content-Type: application/json' -H 'Accept: application/json' \
  -d '{"fqdn":"_acme-challenge.www.example.com.","value":"challenge-token"}' \
  http://127.0.0.1:9090/cleanup
```

Use `https://...` if the proxy (or a front-end) terminates TLS.
