# 0002. Kuma runs with "Disable Auth" behind the gate

- Status: Accepted
- Date: 2026-11-19

## Context

Uptime Kuma (2.5.12) has one user and no SSO. We want several people to manage it, each with
their own sign-in (local accounts with TOTP, Mastodon roles, OIDC), and its status pages,
badges and push URLs to stay public. Kuma's "Disable Auth" setting logs every socket.io
connection in as its only user (`server/server.js:1756`, `autoLogin`) and opens `/metrics`
(`server/auth.js:155`, `apiAuth`). Anyone who reaches Kuma's port is then its admin.

## Decision

Kuma runs with "Disable Auth" on and listens only on localhost (or a private network), and
kuma-gate is the only way to it. The gate:

- lets through without a session only an exact list of public paths and methods, taken from
  Kuma's source with file:line references (`policy.go`); everything else is denied by default;
- decides on the exact path it forwards: any percent-encoding, backslash, `//`, `.`/`..`
  segment or `;` is a 400, so the gate and Kuma never read a path differently;
- serves Kuma's admin UI only on the BaseURL host; other hosts get the public paths or a 404,
  never a sign-in page (since 0.1.1 a page visit there is redirected to the same path on the
  BaseURL host, a fixed host, so the sign-in still happens in one place);
- requires a goweb session at level admin and one of the `User.Key()` values in `gate.admins`;
  letting in every admin needs the explicit `gate.allow_all_admins: true`, and a missing,
  empty or misspelled section stops the start (fail closed);
- refuses socket.io, upgrades and unsafe methods from another origin, and socket.io and
  upgrades that carry neither `Origin` nor `Sec-Fetch-Site: same-origin`;
- re-checks the session cookie of an open websocket every 30 s and closes it when that session
  ends;
- drops the query string on public routes whose Kuma handler ignores it, so it cannot bypass
  Kuma's response cache;
- strips its own cookies before forwarding and sets X-Forwarded-* itself.

## Consequences

- Everyone who passes the gate is Kuma's single admin: Kuma's own audit trail cannot tell people
  apart. The gate's log (sign-in events, refusals) is the record of who got in.
- A misconfigured Kuma (port published on 0.0.0.0, or reachable from another container or host)
  is fully open: with Docker, a published port bypasses the host firewall. The README says so first.
- A new Kuma version may add routes. New private routes are safe (default deny); new public
  ones stay closed until added to `policy.go` with their source line. Review `policy.go` against
  Kuma's `server/routers/` and `src/router.js` on every Kuma upgrade.
- Sessions are signed cookies; the gate cannot revoke one. POST /logout only clears the cookie
  in that browser: a Kuma tab already open elsewhere keeps admin until the session expires
  (`session_ttl`, 4 h in the examples). Only "sign out everywhere" (`/account/signout-all`) or a
  change to the account (password, TOTP reset, level, disable) ends local sessions everywhere;
  for Mastodon and OIDC, only the expiry or removal from `gate.admins` (and a restart) does.
  goweb is not changed for this; a server-side revocation list would be the fix if needed.
- The local accounts' sign-in limits use `KUMAGATE_TRUSTED_PROXIES` (passed on by the gate), so
  there is one setting and a container bridge doesn't turn every sign-in into one address.
- Revisit if Kuma gains real multi-user or SSO support, or a trusted-header auth mode.
