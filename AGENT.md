# AGENT.md

Guidelines for changes to ghook. Applies to code, UI, docs and releases.

## Product principle

Ghook is a self-hosted Gmail push router: Gmail `users.watch` in, webhook POST out. Users are not Google Cloud or OAuth experts. The lead is always that path. Claims stay modest: no "only" and no "first".

- Prefer secure defaults that adapt automatically over config toggles.
- Minimize settings. Every new option needs a reason a default cannot cover.
- Pull is the default Pub/Sub mode. Push is optional.
- Apply this to every design decision.

## Style

- Technical audience. No fluff, no hand-holding, short lines.
- UI copy: short, plain, direct, in the voice of the rest of the app. Labels are nouns or verbs. A hint is one short sentence, and most fields need none. No filler or marketing words, no "Let's", no explanatory paragraphs, no parentheticals, no em dashes.
- Generic examples only (`ghook.example.com`, `ada@example.com`, `admin@example.com`). No house-specific names, no personal data, no real mailboxes or tokens in code, docs, tests or screenshots.
- One version display: semver (`vX.Y.Z`), in the header only.
- README is for operators. It stays educational and brief. Logging, transactions, CSS rules, the wordmark, CI and the release process stay out of the front page. They live here.

## UI

- Shared styles and components, never page by page. New markup goes in `internal/web/templates/components.html` and `internal/web/static/app.css`. No inline `style=` or `on*=`, and no page-specific CSS rules.
- The top bar is sticky on every page and width (`position:sticky;top:0`, opaque, `--z-header`, below menus, dialogs and `--z-toast`). `--header-h` (kept by `app.js`) is the `scroll-padding-top`. Below 800 px it is one row: brand, current page name, a Menu button. The links, version, user and logout fold into `.nav-panel`. Wider windows keep the links in the bar. Standalone screens (login, privacy, terms) have no bar.
- No horizontal overflow, down to 360 px, on any public or admin page. Inline `code` and `.code` wrap (`white-space:normal`, `overflow-wrap:anywhere`, `overflow-x:visible`). Never set `white-space:nowrap` with `overflow-x:auto` on inline code. `pre` wraps. Tables and cards do not create a page or element horizontal scrollbar. After a CSS or template change, run the headless overflow audit at 1280, 768 and 375 (and 360 if the layout changed).
- The product name in visible prose uses the reusable wordmark: `<span class="gh-word">ghook</span>` (keep the original capitalization, including `Ghook`). The class is `#ffd100` with a soft yellow `text-shadow`. Do not wrap the word inside code chips (`Ghook/CFO`, `X-Ghook-Delivery`), form values, placeholders, `<option>` text, or the document `<title>`. Dynamic errors and toasts go through the `wordmark` template func, which escapes first and matches the whole word only.
- Chips that name a label path show the full text and wrap, never an ellipsis. Write `Ghook/Routed/<target>`, not `Ghook/Routed/…`.
- List tables are tables above 800 px and a stack of cards below it, from the same markup. Every data cell on those tables carries `data-label`.
- No page is rendered by a POST. Screens are GET and can be refreshed. A change is a POST that answers 303 to a screen.

## Security

- Secrets are never logged, never put in URLs, never shown again in the UI after they are saved, and never committed. The UI shows that a secret is saved and lets you replace or clear it.
- Do not print OAuth client JSON, service account keys, refresh tokens, `SECRETS_KEY`, session cookies, or Authelia and Traefik secrets.
- Examples use only generic hostnames and addresses. No personal data in fixtures, docs, tests, screenshots or commit messages.

## Code

Repo layout:

| Path | |
| --- | --- |
| `cmd/ghook` | Server and CLI (`healthcheck`, `export`, `import`, `replay`) |
| `internal/web` | Admin UI, templates, static assets, public `/healthz` and `/hooks/pubsub` |
| `internal/engine` | Watch, history, routing into the outbox |
| `internal/deliver` | POST, retries, digest, quiet hours |
| `internal/match` | Route filters and the `Ghook/<target>` label convention |
| `internal/pubsubx` | Pull and optional push |
| `internal/gmailx` | Gmail API |
| `internal/store` | SQLite and migrations |
| `internal/config` | Boot environment |
| `internal/secrets` | Sealed tokens |
| `internal/bundle` | YAML export and import |
| `internal/oidcauth` | Admin OIDC |
| `docs/img` | Logo |

Invariants. Do not weaken these:

- The mailbox `historyId` moves forward in the same transaction as the outbox inserts.
- The Pub/Sub message is acked only after that commit.
- A unique `(account, message id, route)` constraint drops duplicates. Replay mints a new delivery id. Retry keeps the same id.
- Catch-up lists history on an interval (default 30 minutes) because notifications get dropped. If Gmail says the history id is too old, ghook lists the resync window (default 2 days) and the constraint sorts out the overlap.

Other conventions:

- Small, meaningful commits with a message body. One concern per commit.
- Tests are required. Before you push, run:

  ```sh
  test -z "$(gofmt -l .)" && go vet ./... && go test ./...
  ```

  CI runs the same three on every push and pull request.
- Database changes are additive and backward compatible.
- Boot settings come from the environment (see `.env.example`). Runtime configuration (Google, routes, targets, retention) lives in SQLite.
- Update README and `.env.example` in the same change when you add or rename a boot variable.

## Release

The default branch is `main`.

1. Land the change on `main`. CI on `main` must be green.
2. Set `Version` in `internal/config/config.go` to `X.Y.Z` in the release commit if it is not already there.
3. Tag `vX.Y.Z` (annotated) and push the tag. Do not push a tag until you mean to release.
4. The Release workflow, on `v*` tags, runs the tests, builds `linux/amd64` and `linux/arm64`, and publishes `ghcr.io/helv-io/ghook` as `vX.Y.Z`, `X.Y.Z`, `latest`, and the 12-character SHA. It also opens a GitHub Release for a stable `vX.Y.Z`.
5. Deploy from that image only. Komodo (or `docker compose`) pulls `ghcr.io/helv-io/ghook:latest` (or the version tag). Do not build the image locally for production.

A manual `workflow_dispatch` of Release tags the image `ci-test-<run id>` only, never a version or `latest`.

## Rules and what enforces them

A rule that nothing enforces is a wish.

| Rule | Enforced by |
| --- | --- |
| `gofmt`, `go vet`, `go test ./...` on every change | CI workflow, and the same commands run locally before a push |
| Version tag `vX.Y.Z` publishes multi-arch images to GHCR | Release workflow on `v*` tags |
| No horizontal scrollbar on admin or public pages | Headless overflow audit at 1280, 768 and 375 after UI changes. Not yet in CI. |
| No personal data in examples, docs or tests | Review |
| Work on a branch. Do not merge, tag or deploy unless asked | Review |
