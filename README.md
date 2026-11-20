# kuma-gate

A sign-in in front of [Uptime Kuma](https://github.com/louislam/uptime-kuma). Kuma has one
user and no SSO; kuma-gate lets several people in, each with their own account (local accounts
with a password and TOTP, a Mastodon instance, or any OpenID Connect provider), and keeps Kuma's
status pages, badges and push URLs public. Built and tested against **Uptime Kuma 2.5.12**.

> **Before you start**
>
> 1. **Kuma must have Settings → Security → "Disable Auth" ON.** kuma-gate does the sign-in;
>    Kuma then logs every connection in as its only user. That is what makes this work, and
>    also what makes step 2 essential.
> 2. **Kuma's port must listen only on localhost or a private network**, never on a public
>    address. With Docker, publish it as `127.0.0.1:3001:3001` (or not at all), never `3001:3001`:
>    a port published on `0.0.0.0` goes through Docker's own iptables rules and **bypasses the
>    host firewall** (ufw, firewalld), so "the firewall blocks 3001" is not enough. If anyone can
>    reach Kuma's port directly, they are Kuma's admin, and `/metrics` is open too.
> 3. **Everyone who passes the gate is Kuma's admin.** Kuma has a single user, so there are no
>    per-person permissions inside Kuma and its own logs cannot tell people apart; kuma-gate's
>    log says who signed in.

## Contents

- [Using it](#using-it)
- [Install](#install)
  - [1. Local accounts (the default)](#1-local-accounts-the-default)
  - [2. Mastodon](#2-mastodon)
  - [3. Both together](#3-both-together)
  - [4. OpenID Connect](#4-openid-connect)
  - [nginx](#nginx)
  - [systemd](#systemd)
  - [Settings](#settings)
- [What stays public](#what-stays-public)
- [Testing and security](#testing-and-security)
- [Architecture](#architecture)
- [Development](#development)
- [License](#license)

## Using it

- Open the admin host (`KUMAGATE_BASE_URL`, e.g. `https://status.example.org/dashboard`). Without
  a session you are sent to `/login`, and back to where you were after signing in.
- Status pages (`/status/<slug>`), badges and push URLs work for everyone, without signing in,
  on the admin host and on the status-only hosts (`KUMAGATE_STATUS_HOSTS`). On a status-only
  host anything else is a 404: no sign-in page there.
- To sign out, open `/logout` and press the button. Local accounts change their password and
  TOTP on `/account`; local admins manage accounts on `/admin/users`.
- Signed in but not allowed (not an admin, or not in the `gate.admins` list)? You get a page
  saying so, with a sign-out button.
- Pages are in Portuguese and English (the browser's language, or the PT/EN links).

## Install

You need Go 1.26+ to build (or the container image, see `docker-compose.yml`), and an nginx (or
any reverse proxy) with TLS in front. kuma-gate listens on `127.0.0.1:3003`; Kuma on
`127.0.0.1:3001`.

```sh
git clone https://gitlab.gutocarvalho.net/open/gcn/kuma-gate.git
cd kuma-gate
CGO_ENABLED=0 go build -trimpath -o kuma-gate .
sudo install -m 0755 kuma-gate /usr/local/bin/kuma-gate

sudo useradd --system --home-dir /var/lib/kuma-gate --shell /usr/sbin/nologin kuma-gate
sudo install -d -m 0750 -o root -g kuma-gate /etc/kuma-gate
sudo install -d -m 0700 -o kuma-gate -g kuma-gate /var/lib/kuma-gate
```

Then pick how people sign in. Every setup has the same two files:

- `/etc/kuma-gate/kuma-gate.env`: the variables, secrets included (`root:kuma-gate`, mode `0640`);
- `/etc/kuma-gate/config.yaml`: the providers and the allowlist, no secrets (`root:kuma-gate`, `0640`).

### 1. Local accounts (the default)

Accounts kept by kuma-gate: a password (argon2id) and, for admins, a TOTP code from an
authenticator app. Nothing external to depend on.

**Generate the two secrets.** They must be different: the first signs the session cookies, the
second seals the TOTP secrets on disk.

```sh
openssl rand -base64 48   # KUMAGATE_SECRET
openssl rand -base64 48   # KUMAGATE_AUTH_KEY (a different value)
```

**`/etc/kuma-gate/kuma-gate.env`**

```sh
KUMAGATE_BASE_URL=https://status.example.org
KUMAGATE_STATUS_HOSTS=status.example.com
KUMAGATE_UPSTREAM=http://127.0.0.1:3001
KUMAGATE_AUTH_CONFIG=/etc/kuma-gate/config.yaml
KUMAGATE_SECRET=paste-the-first-value-here
KUMAGATE_AUTH_KEY=paste-the-second-value-here
```

**`/etc/kuma-gate/config.yaml`**

```yaml
auth:
  session_ttl: 8h
  providers:
    - id: local
      type: local
      label: Local account
      totp_level: admin
      users_file: /var/lib/kuma-gate/users.json
      trusted_proxies: [127.0.0.1, "::1"]
gate:
  admins: [local:ana]     # optional; without it every local admin gets in
```

```sh
sudo chown root:kuma-gate /etc/kuma-gate/kuma-gate.env /etc/kuma-gate/config.yaml
sudo chmod 0640 /etc/kuma-gate/kuma-gate.env /etc/kuma-gate/config.yaml
```

**Create the first admin.** The command line reads the same variables and YAML as the server,
so run it as the service user with the env file loaded. Either type the password in:

```sh
read -rs PW && printf '%s\n' "$PW" | sudo -u kuma-gate sh -c 'set -a; . /etc/kuma-gate/kuma-gate.env; exec kuma-gate user add ana admin --password-stdin'; unset PW
# type the password (12 to 256 characters, not echoed), then Enter
```

or let it make one, printed once:

```sh
sudo -u kuma-gate sh -c 'set -a; . /etc/kuma-gate/kuma-gate.env; exec kuma-gate user add ana admin'
# account ana created (admin)
# password: ...
# it will set up TOTP at the first sign-in
```

Passwords never go on the command line (they would stay in the shell history).

**First sign-in.** Start the service ([systemd](#systemd)), open
`https://status.example.org/login`, type the name and password. An admin account must set up
TOTP before getting in: scan the QR code with an authenticator app (Aegis, 2FAS, Google
Authenticator, 1Password...) or type the key shown, then type the 6-digit code. From then on
each sign-in asks for the password and a code.

**Managing people.** Local admins open `/admin/users` to create accounts, change a level, set a
new password, reset someone's TOTP, and turn accounts off and on. Each person changes their own
password on `/account`. Only `admin` accounts reach Kuma: `viewer` and `editor` accounts exist in
goweb, but kuma-gate lets them in nowhere. If `gate.admins` is set, only the listed admins may
use `/admin/users` too.

**Recovery from the command line** (same `sudo -u kuma-gate sh -c '...'` wrapper as above):

| Command | What it does |
|---|---|
| `kuma-gate user list` | accounts, levels, TOTP on/off, state |
| `kuma-gate user passwd ana [--password-stdin]` | new password; ends ana's sessions |
| `kuma-gate user totp-reset ana` | lost phone: ana sets up TOTP again at the next sign-in |
| `kuma-gate user level ana admin` | change the level |
| `kuma-gate user disable ana` / `enable ana` | turn the account off and on |
| `kuma-gate user delete ana` | remove it |

Every change but `enable` ends the account's open sessions, including an open Kuma tab (the
websocket closes within 30 seconds).

### 2. Mastodon

People sign in with their account on a Mastodon instance; the instance's **role** decides who
is an admin here.

**On the instance**, signed in as anyone who will own the app: Preferences → Development → New
application.

- Application name: `kuma-gate` (anything).
- Redirect URI: `https://status.example.org/auth/callback` (your `KUMAGATE_BASE_URL` + `/auth/callback`).
- Scopes: untick everything except **`profile`**. kuma-gate only reads who you are and your role,
  and revokes the token at once.

Submit, open the app, and copy the **Client key** and **Client secret**.

**`/etc/kuma-gate/kuma-gate.env`**: the same base as above (without `KUMAGATE_AUTH_KEY`, which only
local accounts need), plus the two values under names of your choice:

```sh
KUMAGATE_BOLHA_CLIENT_ID=the-client-key
KUMAGATE_BOLHA_CLIENT_SECRET=the-client-secret
```

**`/etc/kuma-gate/config.yaml`**: the YAML names those variables; the values stay in the env file.

```yaml
auth:
  session_ttl: 8h
  providers:
    - id: bolha                      # your name for this provider: used in gate.admins
      type: mastodon
      label: bolha.us                # shown on the sign-in page
      instance: https://bolha.us
      client_id_env: KUMAGATE_BOLHA_CLIENT_ID
      client_secret_env: KUMAGATE_BOLHA_CLIENT_SECRET
      roles: {Fundador: admin, "Sábios": admin}
gate:
  admins: [bolha:gutocarvalho, bolha:robertomurta, bolha:ulyssesalmeida]
```

- **`roles`** maps the instance's role names (as in its admin panel, Administration → Roles; case
  does not matter) to a level. Only `admin` reaches Kuma. An account whose role is not listed cannot sign in.
- **`gate.admins`** narrows it to specific people: `<provider id>:<username>`, here three people
  of bolha.us. Others with the same role sign in but get the "not allowed" page. Use it when a
  role is shared by more people than should manage your monitoring. Without the list, every
  account with an `admin`-mapped role gets in.
- **`sign_in_without_role: true`** lets accounts with no listed role sign in, at no level. They
  are still refused by kuma-gate (it needs `admin`), so it changes only which page they see;
  you rarely need it here.

The username is the account's `acct` on its own instance (`gutocarvalho`, not
`gutocarvalho@bolha.us`). Kuma's admin pages work as before; the Mastodon token is never kept.

### 3. Both together

One YAML with both providers: the sign-in page lists them and each person picks one. Keep a
local admin as a fallback: **if the Mastodon instance is down (or its role setup changes), you
can still reach your monitoring**, which is exactly when you need it.

```yaml
auth:
  session_ttl: 8h
  providers:
    - id: local
      type: local
      label: Local account (fallback)
      totp_level: admin
      users_file: /var/lib/kuma-gate/users.json
      trusted_proxies: [127.0.0.1, "::1"]
    - id: bolha
      type: mastodon
      label: bolha.us
      instance: https://bolha.us
      client_id_env: KUMAGATE_BOLHA_CLIENT_ID
      client_secret_env: KUMAGATE_BOLHA_CLIENT_SECRET
      roles: {Fundador: admin, "Sábios": admin}
gate:
  admins:
    - local:guto
    - bolha:gutocarvalho
    - bolha:robertomurta
    - bolha:ulyssesalmeida
```

The env file then has `KUMAGATE_SECRET`, `KUMAGATE_AUTH_KEY` and the two Mastodon variables.
`local:ana` and `bolha:ana` are two different people. A typo in `gate.admins` (an unknown
provider id, a missing `:`) stops the start with a message instead of locking you out.
[`config.example.yaml`](config.example.yaml) has all of this, commented.

### 4. OpenID Connect

Any OIDC provider (Authentik, Keycloak, GitLab, Google...) works the same way: an entry with
`type: oidc`, `issuer`, the client id/secret variables and `roles` mapped from a claim (`groups`
by default), callback `<KUMAGATE_BASE_URL>/auth/callback`. See the commented example in
[`config.example.yaml`](config.example.yaml) and the sign-in module's documentation,
[goweb](https://gitlab.gutocarvalho.net/open/gcn/goweb#several-providers-yaml), for every field
and the warning about group names people can create themselves.

### nginx

kuma-gate expects one nginx (or other proxy) on the same machine, with TLS, passing `Host` and
the websocket headers. A full example is in
[`contrib/nginx-kuma-gate.conf`](contrib/nginx-kuma-gate.conf):

```nginx
map $http_upgrade $connection_upgrade {
    default upgrade;
    ''      close;
}

server {
    listen 443 ssl;
    http2 on;
    server_name status.example.org status.example.com;
    ssl_certificate     /etc/letsencrypt/live/status.example.org/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/status.example.org/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:3003;
        proxy_http_version 1.1;
        proxy_set_header Host              $host;
        proxy_set_header X-Forwarded-For   $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Upgrade           $http_upgrade;
        proxy_set_header Connection        $connection_upgrade;
        proxy_read_timeout 1h;
        proxy_send_timeout 1h;
        proxy_buffering off;
    }
}
```

`Host` must be passed through: it decides the admin host versus the status-only hosts, and Kuma
uses it for domain-mapped status pages and its websocket origin check. kuma-gate believes
`X-Forwarded-For`/`-Proto` only from `KUMAGATE_TRUSTED_PROXIES` (default `127.0.0.1,::1`).

### systemd

[`contrib/kuma-gate.service`](contrib/kuma-gate.service), with hardening options:

```ini
[Unit]
Description=kuma-gate, the sign-in in front of Uptime Kuma
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/kuma-gate
EnvironmentFile=/etc/kuma-gate/kuma-gate.env
User=kuma-gate
Group=kuma-gate
StateDirectory=kuma-gate
StateDirectoryMode=0700
UMask=0077
Restart=on-failure
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
```

```sh
sudo install -m 0644 contrib/kuma-gate.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now kuma-gate
journalctl -u kuma-gate -f          # sign-ins, refusals, upstream errors
curl -fsS http://127.0.0.1:3003/healthz
```

Bad settings stop the start with a message saying what is expected (`journalctl -u kuma-gate`).

### Settings

| Variable | Default | Meaning |
|---|---|---|
| `KUMAGATE_BASE_URL` | (required) | the admin host's public URL, without a path |
| `KUMAGATE_AUTH_CONFIG` | (required) | the YAML file: providers and `gate.admins` |
| `KUMAGATE_SECRET` | (required) | signs the cookies, 32+ characters; changing it signs everyone out |
| `KUMAGATE_AUTH_KEY` | | local accounts: seals TOTP secrets, 32+ characters, not the same as the secret |
| `KUMAGATE_STATUS_HOSTS` | | status-only hosts, comma-separated; any other Host gets 404 |
| `KUMAGATE_UPSTREAM` | `http://127.0.0.1:3001` | Kuma, without a path |
| `KUMAGATE_LISTEN` | `127.0.0.1:3003` | address to listen on; the healthcheck follows it |
| `KUMAGATE_TRUSTED_PROXIES` | `127.0.0.1,::1` | proxies whose `X-Forwarded-For`/`-Proto` are believed |
| `KUMAGATE_DATA` | `/var/lib/kuma-gate` | where `users.json` goes if the YAML has no `users_file` |
| `KUMAGATE_LANG` | `en` | language when the browser asks for neither pt nor en |
| `KUMAGATE_FAMILY` | `gcn` | the look: `gcn` (red) or `bolha` (yellow) |

Plus the client id/secret variables your YAML names. The image is
`registry.gutocarvalho.net/images/kuma-gate:<X.Y.Z-BUILD>` (listens on `:3003` inside).

## What stays public

Default deny: only these reach Kuma without a session, with these methods, as exact
case-sensitive paths (the list, with Kuma's source lines, is in [`policy.go`](policy.go)):

| Path | Methods | Kuma 2.5.12 source |
|---|---|---|
| `/` | GET, HEAD | `server/server.js:264` (status page of a mapped domain, else a redirect) |
| `/robots.txt` | GET, HEAD | `server/server.js:342` |
| `/favicon.ico`, `/icon.svg`, `/icon.png`, `/icon-192x192.png`, `/icon-512x512.png`, `/apple-touch-icon.png`, `/manifest.json`, `/serviceWorker.js` | GET, HEAD | `server/server.js:357` (`dist/` from `public/`) |
| `/assets/<file>` (except kuma-gate's own `/assets/style.css`) | GET, HEAD | `server/server.js:357` (Vite's hashed bundles) |
| `/upload/<file>` | GET, HEAD | `server/server.js:365` (status page logos) |
| `/status`, `/status/`, `/status/<slug>`, `/status/<slug>/rss`, `/status-page` | GET, HEAD | `server/routers/status-page-router.js:16-33` |
| `/api/status-page/<slug>`, `/api/status-page/heartbeat/<slug>`, `/api/status-page/<slug>/{manifest.json,incident-history,badge}` | GET, HEAD | `status-page-router.js:39, 64, 113, 145, 170` |
| `/api/entry-page` | GET, HEAD | `server/routers/api-router.js:27` |
| `/api/push/<token>` | GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS | `api-router.js:46` (`router.all`) |
| `/api/badge/<id>/{status,cert-exp,response}`, `/api/badge/<id>/{uptime,ping,avg-response}[/<duration>]` | GET, HEAD | `api-router.js:147-494` |

Everything else needs a signed-in, allowed admin on the admin host: the dashboard and every
other page of Kuma's app, `/metrics` (open in Kuma when auth is disabled), `/screenshots/`,
`/socket.io/`, every other `/api/*`. On other hosts it is a 404.

**socket.io and the status page.** The public status page does not use socket.io: Kuma's
frontend skips it on `/status*`, `/status-page` and `/` (`src/mixins/socket.js:19-23`) and reads
the page over plain HTTP. Only the status page's *edit mode* opens socket.io
(`src/pages/StatusPage.vue`, `edit()`), and that works on the admin host with a session.

**Paths kuma-gate refuses (400).** Any `%`-encoding, a backslash, `//`, a `.` or `..` segment, `;`,
or a non-`/` request target. No Kuma route needs them, and they are how path tricks hide
(`/status/../dashboard`, `/api/push/..%2f..%2fmetrics`). What kuma-gate decides on is exactly
what it forwards.

## Testing and security

**Every pipeline.** GitLab CI ([`.gitlab-ci.yml`](.gitlab-ci.yml), plus the shared security
stage from `open/gcn/ci-templates`) runs on every push to `main` and on merge requests; the
image is built and published only from `main`.

- Blocking: `go vet`, `gofmt`, the tests, `govulncheck`, `betterleaks` (secrets), `trivy`.
- Informative: `gosec`, `semgrep`, `hadolint`, `yamllint`, `poutine`.

**The test suite** runs the real handler against a fake Kuma that records every request it gets
and a fake Mastodon instance:

- every route of Kuma's `src/router.js` and every non-public server route, without a session, on
  all three hosts: none reaches Kuma (redirect to sign-in for a page, 401 for the rest, 404 off
  the admin host); every public path passes on every host with its Host intact;
- path tricks (`..`, `//`, `%2f`, `%2e`, `%5c`, `;`, absolute-form, case) give 400 or are denied;
- the allowlist and the admin level (a Fundador not in `gate.admins` and a viewer are refused),
  cross-origin socket.io and websocket refused, websocket only with a session; a websocket and a socket.io
  long-poll outliving the server's timeouts, and the websocket closing when the session ends;
- the gate's cookies never reach Kuma (and Kuma cannot set them), `X-Forwarded-*` cannot be
  spoofed by a client, body limits, push tokens never in the log, the gate's `/login` and
  `/assets/style.css` win over Kuma while Kuma's `/assets/*` pass;
- the template's rules: security headers and nothing inline on the gate's pages, both languages,
  config validation, the account command line, the healthcheck address.

**Reviews.** None yet beyond the automated checks above.

**Reporting a vulnerability.** Write to contato@gutocarvalho.net. Please don't open a public
issue for it.

## Architecture

**Why it exists.** Kuma has a single user and no SSO; several people need to manage it, and
its status pages must stay public. Why Kuma runs with "Disable Auth" behind the gate, and what
that costs: [docs/decisions/0002](docs/decisions/0002-kuma-disableauth-behind-the-gate.md).

**How it works.** For each request, in order:

1. CONNECT/TRACE → 405; a non-canonical path → 400; `/healthz` answers on any host.
2. A Host that is neither the admin host nor a status host → 404.
3. kuma-gate's own stylesheet; then the public list → proxied to Kuma, no session needed.
4. Not the admin host → 404. The gate's pages (`/login`, `/auth/callback`, `/logout`,
   `/login/totp`, `/account*`, `/admin/users*`, `/release-notes`) → served by the gate. Kuma has
   none of these routes, so nothing of Kuma is hidden.
5. Anything else needs a session: none → `/login?next=...` for a page, 401 otherwise; not an
   admin or not in `gate.admins` → 403; socket.io, upgrades and unsafe methods from another
   origin → 403; otherwise proxied (HTTP and the websocket).

Proxying keeps `Host`, sets `X-Forwarded-For` (one address), `X-Real-IP`, `X-Forwarded-Proto`
and `X-Forwarded-Host` itself, removes the gate's cookies, caps request bodies (128 KiB public,
2 MiB signed in, above socket.io's 1 MB default), and gives proxied requests their own deadlines
(socket.io long-polling waits up to 25 s). A websocket, once upgraded, is not cut by the
server's timeouts; its session is checked every 30 s instead.

```
browser ──HTTPS──▶ nginx ──HTTP──▶ kuma-gate (127.0.0.1:3003) ──HTTP/ws──▶ Uptime Kuma (127.0.0.1:3001)
                                    ├─ goweb sign-in (local / Mastodon / OIDC)
                                    └─ /var/lib/kuma-gate/users.json (local accounts)
```

**Where data lives.** Sessions are signed cookies (no server table). Local accounts are in
`users.json` (argon2id hashes, TOTP secrets sealed with `KUMAGATE_AUTH_KEY`). The log (journald)
has sign-ins and refusals with account and IP, never cookies, tokens or query strings. Kuma keeps
its own data as before.

## Development

See [AGENTS.md](AGENTS.md) for the commands, the map of the code and the rules a change must
keep, and [docs/decisions/](docs/decisions/) for why the expensive choices were made. When Kuma
is upgraded, review [`policy.go`](policy.go) against its routes before deploying.

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE).
