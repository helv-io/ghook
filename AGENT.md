# AGENT.md

Guidelines for changes to ghook. Applies to code, UI, docs and releases.

## Product principle

ghook is a multi-tenant Gmail push router: Gmail `users.watch` in, webhook POST out. Anyone who signs in with Google gets their own isolated account. Users are not Google Cloud or OAuth experts. The lead is always that path. Claims stay modest: no "only" and no "first". There is no owner, invite, or allowlist story.

- Prefer secure defaults that adapt automatically over config toggles.
- Minimize settings. Every new option needs a reason a default cannot cover.
- Pull is the default Pub/Sub mode. Push is optional.
- Apply this to every design decision.

## Style

- Technical audience. No fluff, no hand-holding, short lines.
- The visual system and the GHCR release workflow follow the same conventions as skgate. That connection is for developers; do not mention skgate in the README or in user-facing UI copy.
- UI copy: short, plain, direct, in the voice of the rest of the app. Labels are nouns or verbs. A hint is one short sentence, and most fields need none. No filler or marketing words, no "Let's", no explanatory paragraphs, no parentheticals, no em dashes.
- Prefer no example at all: no sample names in placeholders or help text, and no sentence that exists only to give one. Show a format instead (`<target>`, `HH:MM`, `URL KEY`). If a bot or target name is unavoidable, use `Chief of Staff`. Hosts and addresses use `example.com` only. No house-specific names (job titles, real senders, real banks), no personal data, no real mailboxes or tokens in code, docs, tests or screenshots.
- One version display: semver (`vX.Y.Z`), in the header only.
- README is for operators. It stays educational and brief. Logging, transactions, CSS rules, the wordmark, CI and the release process stay out of the front page. They live here.

## UI

- Shared styles and components, never page by page. New markup goes in `internal/web/templates/components.html` and `internal/web/static/app.css`. No inline `style=` or `on*=`, and no page-specific CSS rules.
- The top bar is sticky on every page and width (`position:sticky;top:0`, opaque, `--z-header`, below menus, dialogs and `--z-toast`). `--header-h` (kept by `app.js`) is the `scroll-padding-top`. Below 800 px it is one row: brand, current page name, a Menu button. The links, version, user and logout fold into `.nav-panel`. Wider windows keep the links in the bar. Standalone screens (login, privacy, terms) have no bar.
- No horizontal overflow, down to 360 px, on any public or admin page. Short code chips and badges do not break mid-word. A checkbox and its label are one inline flow (`label.check` is `display:block` with ordinary wrapping). Never put the label text in flex or grid cells that can shrink mid-word. `.gh-word` is `display:inline;white-space:nowrap` and must never split. Long paths may wrap only at `/` (`code.path`, each segment in `.path-seg`, `<wbr>` after each slash). Never set `white-space:nowrap` with `overflow-x:auto` on inline code. `pre` wraps. Tables and cards do not create a page or element horizontal scrollbar. After a CSS or template change, run `scripts/layout-audit.py` at 1440, 1024, 768 and 390 (and 360 if the layout changed). The audit fails on mid-word wrap, a text run narrower than about three characters, or a wordmark that breaks across client rects. A `scrollWidth` check alone is not enough (`scrollbar-gutter:stable` can hide overflow).
- The product name is always lowercase `ghook`, including the start of a sentence and in titles. The only `Ghook` spellings that stay are ones lowercase cannot express, such as a Go exported identifier or the wire header names `X-Ghook-Delivery` and `X-Ghook-Signature`. In visible prose the name uses the reusable wordmark: `<span class="gh-word">ghook</span>`. The class is `#ffd100` with a soft yellow `text-shadow`. Do not wrap the word inside code chips (`ghook/<target>`, `X-Ghook-Delivery`), form values, placeholders, `<option>` text, or the document `<title>`. Dynamic errors and toasts go through the `wordmark` template func, which escapes first, matches the whole word only, and always renders lowercase.
- Chips that name a label path show the full text and wrap, never an ellipsis. Write `ghook/Routed/<target>`, not `ghook/Routed/…`.
- List tables are tables above 800 px and a stack of cards below it, from the same markup. Every data cell on those tables carries `data-label`.
- No page is rendered by a POST. Screens are GET and can be refreshed. A change is a POST that answers 303 to a screen. Exception: a form with `data-autosave` may answer JSON when the request asks for it (`Accept: application/json` or `X-Requested-With: fetch`) and leave the user on the GET screen. A non-JS POST still answers 303.

## Security

- Secrets are never logged, never put in URLs, never shown again in the UI after they are saved, and never committed. The UI shows that a secret is saved and lets you replace or clear it.
- Do not print OAuth client JSON, service account keys, refresh tokens, `SECRETS_KEY`, session cookies, or Traefik secrets.
- Examples use only generic hostnames and addresses. No personal data in fixtures, docs, tests, screenshots or commit messages.

## Code

Repo layout:

| Path | |
| --- | --- |
| `cmd/ghook` | Server and CLI (`healthcheck`, `export`, `import`, `replay`) |
| `internal/web` | Admin UI, templates, static assets, public `/healthz` and `/hooks/pubsub` |
| `internal/engine` | Watch, history, routing into the outbox |
| `internal/deliver` | POST, retries, digest, quiet hours |
| `internal/match` | Route filters and the `ghook/<target>` label convention |
| `internal/pubsubx` | Pull and optional push |
| `internal/gmailx` | Gmail API |
| `internal/store` | SQLite and migrations |
| `internal/config` | Boot environment |
| `internal/secrets` | Sealed tokens |
| `internal/bundle` | YAML export and import |
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
- 0.1.3 needed a fresh database (a workspace-era file is still an error). 0.1.4 opens a 0.1.3 database and migrates in place: it adds `user_keys` and `targets.payload_pubkey`, mints a per-user DEK, and re-seals `enc:v1` values as `enc:v2`. Do not wipe a 0.1.3 data directory to upgrade. Later changes should stay additive.
- Boot settings come from the environment (see `.env.example`). The Google client and the shared Pub/Sub subscription are instance-wide. Routes, targets, and retention live in SQLite, scoped by `user_id`.
- Every query and admin endpoint is scoped to the signed-in user. Tests must keep proving user A cannot see or modify user B's routes, targets, logs, or Gmail state. The activity feed is per user (`AddFor` / `BacklogFor`).
- Update README and `.env.example` in the same change when you add or rename a boot variable.


## Autosave

There is no Save button on an existing resource. Creation of a new route or target still uses a single Create action. Disconnect, delete, and other destructive actions still use a confirm dialog; those are not saves.

- Forms that edit an existing row have `data-autosave`. The client POSTs the whole `FormData` (so an unchecked box is stored as off) with the CSRF token.
- Checkboxes, selects and toggles save on `change` (100ms debounce). Text inputs save on `blur` and Enter (200ms debounce).
- Skip fields or forms marked `data-no-autosave` (the route simulator's `n` is one). An empty secret field is not sent, so it does not clear the stored secret.
- Validation errors are shown next to the field. A failed save flags or reverts the value and shows an error toast.
- Delete must be its own form. If Delete is the only submit button on the edit form, Enter would fire it.
- Toggling an optional Gmail scope submits the scopes form and starts the Google re-consent redirect. A one-line note on the page says it goes through Google. That is a navigation, not a toast.

## List pages

- Routes: the Match cell is one section per filter field in field order (From, To, Cc, Subject regex, Contains, Labels, Category, Attachment). Values sit one per line. A bar and "any of N" mark an ORed list; the AND/OR joiner between sections is the route operator. More than three values in a section collapse behind a twistie.
- List values (From, To, Cc, Labels) and Subject or Contains edit in place through `POST /admin/routes/field` (`id`, `field`, newline-separated `value`), which answers the stored values as JSON. Category and attachment open the route page.
- `match.SortSenders` orders From, To and Cc on every save: bare domains, then `*.` domains, then full addresses, A to Z, deduped without regard to case.
- One drag handle per row. Only the handle starts a drag; the order saves on drag end. Alt+arrow still moves a focused row.
- Targets show a destination label from the URL host (`targetDest`), never the raw URL. The URL is the title and the Copy URL button.
- Every time on a page is in the user's display timezone. Templates use `when`, `short`, `full` and `clock`; `render` binds them per request to `page.Loc`.

## Toast API

`toast(message, {kind, duration})` in `internal/web/static/app.js`.

- `kind` is `success`, `error`, or `info`. Legacy aliases: `ok` → `success`, `bad` → `error`, `warn` → `info`.
- Default duration: success 1s, error 4s, info 4s. The "Saved" confirmation is exactly 1s (`{kind:"success", duration:1000}`).
- Toasts stack in `.toasts` (`role="status"`, `aria-live="polite"`). The container is always in `layout.html`.
- Placement: bottom-right on desktop, bottom-center below 800px. The stack is `pointer-events:none`; each toast is `auto`. Toasts are non-blocking and must not shift the page layout.
- `prefers-reduced-motion: reduce` disables the fade.

## Forms

- Edit forms show only the essentials: a route is a name, its senders and a target; a target is a name and one "webhook" box that takes `URL KEY` (the handler splits it; a URL alone keeps the saved key). Everything else sits in `<details class="more">` ("More options"), which opens by itself only when `routeAdvanced`, `targetAdvanced` or `settingsAdvanced` sees a non-default value. Add a new advanced field to the matching helper.
- Testing mode (`testing_mode` setting, off by default) shows the route simulator and the replay buttons. It hides UI only; the endpoints stay.

## Database upkeep

- `store.Open` sets pragmas in the DSN (busy_timeout, WAL, `journal_size_limit` 64 MiB, foreign keys) so a reopened connection keeps them. New files use `auto_vacuum=INCREMENTAL`.
- `runtime.compactLoop` runs `purge` then `store.Compact` daily at `COMPACT_AT` (default 03:15, `off` disables), and once ~30s after start when `FileStats.NeedsCompact` (a quarter of the file free and at least 8 MiB, or a WAL of 64 MiB or more). `Compact` checkpoints with TRUNCATE, runs one full `VACUUM` on a file that is not yet incremental (which converts it), then `incremental_vacuum` after that. A second call while one runs returns `ErrCompactBusy`. The last run is the instance setting `compact_last`.
- Never seal a value that is already sealed; use `sealOnce`. Sealing a sealed token nests it and the row grows by a third on every save. `openDeep` unwraps such values on read.
- `gmailx.savingSource` starts with the cached access token so it only writes back after a real refresh, not on every `Dial`.

## Data protection

ghook must read mail in memory to decide a route, so this is not end-to-end encryption. Be honest about that in the README and the privacy page. Confidential VMs are a possible future hardening, not something this version does.

What is stored:

- Delivery logs keep metadata (message id, route, target, status, timing). Email bodies and snippets are not written unless the user turns `retain_bodies` on. Retained payloads, request logs and response bodies are sealed and purged after the retention window.
- Login and mailbox addresses (`users.email`, `accounts.email`) stay in the clear. They are lookup keys for the shared Pub/Sub `emailAddress`.
- Route `match_json` is sealed (it can hold addresses and subject patterns).

Envelope encryption at rest:

- Each user has a random DEK, wrapped by the instance KEK and stored in `user_keys`. The KEK is `SECRETS_KEY` or `/data/secrets.key`. `secrets.KEK` is the interface; `LocalKEK` is the current implementation. A GCP KMS wrapper can be plugged in later without changing callers.
- New ciphertext uses `enc:v2:` (the DEK). `Open` still accepts `enc:v1:` (the previous HMAC-derived key) so a 0.1.3 database keeps working until the first `Use` re-seals those rows.
- Sealed fields: Google refresh and access tokens, target secrets and auth headers, any stored payloads, and `routes.match_json`.
- `ghook keys rotate [--user EMAIL|ID|--all]` mints a new DEK and re-seals. `ghook keys rotate-kek` re-wraps every DEK and swaps the key file (file-backed KEK only; `SECRETS_KEY` must be unset). The previous file is kept as `secrets.key.bak`. Neither command prints key material.
- Deleting an account destroys the wrapped DEK first in the same transaction (crypto-shred), then deletes the rows.

Optional per-target payload encryption: a target may supply an `age1…` X25519 public key. ghook encrypts the outbound body (`Content-Type: application/age`, `X-Ghook-Encrypted: age`). The HMAC is over the bytes actually sent. Only the holder of the matching secret can read that body.

Logs and metrics never include secrets. Email addresses in logs are redacted (`ada@example.com` → `a***@example.com`). `/metrics` is aggregate only and includes no emails.

A stolen database file without the KEK cannot open tokens, secrets, or sealed payloads. An operator who has both the database and the KEK can. Document that plainly.

Tests must cover an encryption round-trip, DEK rotation, crypto-shred, a v1→v2 migration, and a grep of the SQLite file for plaintext secrets.

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
