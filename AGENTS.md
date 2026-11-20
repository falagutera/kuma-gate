# AGENTS.md — kuma-gate

An authenticating reverse proxy in front of Uptime Kuma 2.5.12 running with "Disable Auth":
goweb sign-in, then Kuma (HTTP + socket.io websocket); Kuma's public paths pass without a
session. Read [docs/decisions/0002](docs/decisions/0002-kuma-disableauth-behind-the-gate.md)
before changing what passes.

## Commands

```sh
gofmt -l .                  # must print nothing
go vet ./...
go test -p 1 ./...          # what CI runs (no -race: CI builds with CGO_ENABLED=0)
go install golang.org/x/vuln/cmd/govulncheck@v1.9.0 && "$(go env GOPATH)/bin/govulncheck" ./...
~/storage/bin/sec-check .   # the CI security gates, locally
docker build --build-arg BUILD=local -t kuma-gate:local .
```

Run it: copy `.env.example` and `config.example.yaml`, start a Kuma on 127.0.0.1:3001, then
`set -a; . ./.env; set +a; go run .`. Settings are KUMAGATE_* variables plus the YAML file.

## Map

| File | What it holds |
|---|---|
| `main.go` | config from env and the YAML (`gate.admins`), validation, `-healthcheck`, `kuma-gate user ...`, the HTTP server with its timeouts, graceful shutdown |
| `policy.go` | **the public path list with Kuma source refs**, path canonicalisation (`canonical`), host normalisation, log redaction of push tokens |
| `server.go` | the decision in `serve` (method, path, health, host, gate assets, public, gate pages, session + allowlist + origin), security headers on gate responses, pages |
| `proxy.go` | `httputil.ReverseProxy` (Rewrite): Host kept, X-Forwarded-* set, gate cookies stripped both ways, body limits, per-request deadlines, websocket session re-check, 502 page |
| `i18n.go` | every text in pt and en; language from `?lang=`, cookie, Accept-Language, KUMAGATE_LANG |
| `version.go` | version `X.Y.Z-BUILD` from `VERSION` + CI build number; releases from `CHANGELOG.md` |
| `internal/relnotes/` | copy of open/gcn/relnotes (update with its `sync.sh`, never by hand) |
| `templates/` | `base.html` (head/foot), `error.html` (also the 403 with sign-out), `logout.html`, `notes.html` |
| `assets/` | `style.css` (copy from open/gcn/ui, never edited here); served only at its exact path, the rest of `/assets/` is Kuma's |
| `VISUAL.md` | the visual standard (copy from open/gcn/ui) |
| `harness_test.go` | test harness: a fake Kuma that records hits (and echoes websockets), a fake Mastodon, the config |
| `gate_test.go` | every Kuma route without a session, public paths on every host, path tricks, allowlist, origin, cookies, forwarded headers, limits, redaction |
| `ws_test.go` | websocket only with a session, outliving the server timeouts, closing when the session ends |
| `server_test.go` | template rules: headers, nothing inline, texts, config validation, CLI, healthcheck |
| `config.example.yaml`, `.env.example` | the settings, documented |
| `contrib/` | systemd unit and nginx example |
| `.gitlab-ci.yml` | shared security stage + test job + image build on `main` |
| `Dockerfile`, `docker-compose.yml` | the container alternative |
| `docs/decisions/` | 0002: why Kuma runs with Disable Auth behind the gate |

## Rules a change must keep

1. **Security headers on every response the gate writes** (pages, errors, redirects, its CSS;
   never on Kuma's proxied responses, see `securityHeaders`): strict CSP with no
   `unsafe-inline`, `nosniff`, `Referrer-Policy`, frame denial (`TestSecurityHeadersEverywhere`).
   Pages have no inline script, style or event handler (`TestPagesHaveNothingInline`). If a page
   needs more, loosen one directive and write why next to it.
2. **No internal detail on a page.** Database, upstream or file errors are logged; the visitor
   gets the translated error page with the status (`renderError`). Panics cost one request a 500
   (`TestPanicIsContained`).
3. **The healthcheck follows KUMAGATE_LISTEN** in every form (`:8080`, `0.0.0.0:9000`, `[::1]:7000`)
   (`TestHealthURL`). Never hardcode the port anywhere else.
4. **Timeouts and limits.** The server has read/write/idle timeouts and a header limit. Every
   handler's own work (outbound calls included) must finish well inside `WriteTimeout`;
   proxied requests are the deliberate exception (own deadlines in `proxy.go`). Every
   read from the network or a client has a size limit (`http.MaxBytesReader`, `io.LimitReader`).
   Outbound HTTP clients have a timeout.
5. **Both languages.** Every text exists in pt and en (`TestTextsInBothLanguages`); e-mails and
   messages the app sends too.
6. **Tests run in CI for real.** If a test needs PostgreSQL or Redis, add the service to the CI
   test job (template in `.gitlab-ci.yml`) and make the test refuse a database whose name does
   not end in `_test`. A test skipped in CI is a gap.
7. **Config only from env**, validated at start with a message that says what is expected.
   Secrets never in the repository, the image or the logs.
8. **Container**: static binary, distroless nonroot (65532), read-only root, no capabilities.
9. **The look is [VISUAL.md](VISUAL.md)**, from `open/gcn/ui`: `assets/style.css` and
   `VISUAL.md` are copies made by its `sync.sh` (never edit them here; app rules go in a second
   stylesheet) and its `check.sh` must pass. Light and dark, system fonts, header with the
   bubble, hero, cards, pills, the fixed footer, badges explained on the page. `KUMAGATE_FAMILY` (`bolha` yellow, `gcn` red) sets the accent;
   `new.sh` picks it from the path (`TestFamily`).
10. **Expensive decisions are written down** in `docs/decisions/` (see its README), in the same
    commit as the change. Read them before undoing something that looks odd.
11. **Default deny.** A path is public only if it is in `publicRoutes` with its Kuma source
    line, and a test in `gate_test.go` lists it. Every Kuma upgrade: diff Kuma's
    `server/server.js`, `server/routers/` and `src/router.js`, and update `policy.go` and the
    route tables in the tests.
12. **Decide on what is forwarded.** `canonical` refuses anything ambiguous; the upstream URL has
    no path; never add decoding or cleaning after the decision.
13. **Nothing secret in logs**: push tokens go through `redactPath`/`redactText`/`firstSegment`,
    no query strings, no cookies (`TestPushTokensNeverLogged`).

## Releasing

- `VERSION` holds `X.Y.Z`; CI adds the build number (`X.Y.Z-BUILD`, shown in the footer and in
  `/release-notes.json`). A fix is a patch, a new feature or option a minor, a breaking change a
  major; docs, tests or CI alone need no bump.
- Every version needs its `CHANGELOG.md` entry (`TestChangelogHasVersion`). It is also the public
  `/release-notes` page, so write it for the people who use the app. Unreleased work can sit
  under `## Unreleased`.
- Images go to `registry.gutocarvalho.net/images/<app>` (never the project's own registry). Pin
  the immutable `X.Y.Z-BUILD` tag in deployments.
- Code, comments, commits and the README in English; the app's pages in pt and en. Keep commits
  small with a message that says why.

## Security checks

CI runs `go vet`, the `gofmt` check, the tests and govulncheck in the test job, and the shared
security stage from open/gcn/ci-templates: betterleaks, govulncheck and trivy block; gosec,
semgrep, hadolint, yamllint, shellcheck and poutine inform. Fix findings at the root; for a
false positive use a narrow `#nosec G### -- reason`, never a broader exception. Before a
release that touches sign-in, permissions, outbound requests or user content, also review it
by hand (`bolha-sec` modes 1+2): scanners don't see authorization.
