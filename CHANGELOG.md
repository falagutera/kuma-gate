# Changelog

All notable changes to kuma-gate. Versions follow [SemVer](https://semver.org/); images are
published as `registry.gutocarvalho.net/images/kuma-gate:<version>-<build>`.

## 0.1.0 — 2026-11-19

- First version: a sign-in in front of Uptime Kuma 2.5.12 (run with "Disable Auth" on). People
  sign in with local accounts (password + TOTP), Mastodon or OpenID Connect, and only admins
  (optionally only the people listed in `gate.admins`) reach Kuma's dashboard and its live
  connection.
- Status pages, badges and push URLs keep working without signing in, on the main host and on
  extra status-only hosts; everything else of Kuma is closed there.
- Odd-looking addresses (`..`, `//`, encoded slashes) are refused; push tokens never reach the log.
- The YAML must say who gets in: `gate.admins` (a list of people) or, explicitly,
  `gate.allow_all_admins: true`. A missing, empty or misspelled section stops the start.
- Query strings reach Kuma only where Kuma reads them (push, badges, incident history), so
  random ones cannot bypass Kuma's response cache.
- `/logout` page with a sign-out button; local accounts also get "Sign out everywhere", which
  closes Kuma tabs open in other browsers. Pages in Portuguese and English, release notes at
  `/release-notes`, health check at `/healthz`.
