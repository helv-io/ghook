<p align="center"><img src="docs/img/logo.svg" width="72" alt="ghook logo"></p>
<h1 align="center">ghook</h1>

<p align="center">Self-hosted Gmail push router. One <code>users.watch</code>, a pull subscription, and a WebUI that sends each new message to the webhook that should have it.</p>

<p align="center">Friendly, like a small appliance. The database holds the configuration. The environment only has to boot.</p>

## Name

**ghook** /ˈdʒiːhʊk/

Gmail, plus the hook a message hangs on. The mark is the same family as [skgate](https://github.com/helv-io/skgate): a dark tile, a yellow letter, a white accent.

## Quick start

You need an [OIDC provider](#admin-sign-in) with a confidential client for ghook. Trying it on one machine with no provider of your own? `docker-compose.quickstart.yml` runs ghook next to Dex.

```yaml
# docker-compose.yml
services:
  ghook:
    container_name: ghook
    image: ghcr.io/helv-io/ghook:latest
    restart: always
    ports:
      - 8080:8080
    environment:
      - PUBLIC_URL=https://ghook.example.com
      - OIDC_ISSUER=https://auth.example.com
      - OIDC_CLIENT_ID=ghook
      - OIDC_CLIENT_SECRET=change-me
    volumes:
      - ./data:/data
    healthcheck:
      test: ["CMD", "/ghook", "healthcheck"]
      interval: 30s
      timeout: 5s
      retries: 3
```

1. `docker compose up -d`
2. Open `https://ghook.example.com/admin` and sign in.
3. **accounts**: paste the Google OAuth client, connect a mailbox, set the Pub/Sub topic.
4. **targets** and **routes**: say where mail goes.

Image: `ghcr.io/helv-io/ghook`. Tags follow the git tag (`v0.1.0`, `0.1.0`, `latest`).

To upgrade, copy `./data` somewhere safe, then `docker compose pull && docker compose up -d`.

### One machine, no identity provider

```sh
docker compose -f docker-compose.quickstart.yml up -d
```

Open `http://localhost:8080/admin`. Sign in as `admin@example.com` / `password`. The login, the client secret and plain HTTP are public knowledge. Do not expose it. Google is still configured in the UI afterwards.

### Traefik

Drop `ports` and add the proxy network:

```yaml
labels:
  - traefik.enable=true
  - traefik.http.routers.ghook.rule=Host(`ghook.example.com`)
  - traefik.http.routers.ghook.entryPoints=websecure
  - traefik.http.routers.ghook.tls.certresolver=le
  - traefik.http.services.ghook.loadbalancer.server.port=8080
```

`PUBLIC_URL` must be the `https://` address the browser uses. It is the OAuth redirect and the cookie scope.

## What it does

One Gmail `users.watch` publishes to a Pub/Sub topic. Ghook pulls that subscription in a loop (the pull API, not the gRPC StreamingPull stream). There is no public URL and it works behind NAT. After each batch it calls `history.list`, then `messages.get`, matches routes, and POSTs a JSON payload at each matched target. The Pub/Sub message is acked only after the outbox commit.

The history id is stored per mailbox and moves forward in the same transaction as the outbox inserts. The Pub/Sub message is acked only after that commit. A unique `(account, message id, route)` constraint drops duplicates. Every 30 minutes (configurable) ghook lists history again, because notifications get dropped. If Gmail says the history id is too old, ghook lists the last 2 days and lets the constraint sort out the overlap.

Watches last about 7 days. Ghook renews them on startup and every hour once the expiry is inside two days. A failed renewal shows on the dashboard and can POST a notice to a target you pick.

## Google setup

Do this once per GCP project.

1. **Create a project and enable the APIs.** In [Google Cloud Console](https://console.cloud.google.com/) create a project, then enable the Gmail API and the Cloud Pub/Sub API.

2. **Create the topic and let Gmail publish.**
   ```sh
   gcloud pubsub topics create ghook
   gcloud pubsub topics add-iam-policy-binding ghook \
     --member=serviceAccount:gmail-api-push@system.gserviceaccount.com \
     --role=roles/pubsub.publisher
   ```
   The UI can do both of these after you save credentials (**Create topic and pull subscription**, **Grant Gmail publish**).

3. **Create a pull subscription.**
   ```sh
   gcloud pubsub subscriptions create ghook-pull --topic=ghook \
     --ack-deadline=60 \
     --message-retention-duration=7d \
     --expiration-period=never
   ```
   Ack deadline 60 seconds, retention 7 days, and no expiration. Pull needs no public endpoint.

4. **OAuth consent screen and client.**
   - Consent screen: External, app name, a support email you control, and your address as a test user.
   - Scopes: add `https://www.googleapis.com/auth/gmail.readonly`. Add `gmail.modify` only if you want ghook to apply labels. Add `gmail.settings.basic` only if you want ghook to create filters.
   - Client: Web application. Authorized redirect URI = ghook's public URL + `/admin/google/callback`, for example `https://ghook.example.com/admin/google/callback`. The wizard shows the exact value and copies it.
   - Download the client JSON and paste it on **accounts**.

5. **Publish the app to production.** A consent screen left in Testing expires refresh tokens after 7 days, and the watch then dies with them. Publishing to production (no verification required for a personal account you click through) keeps the refresh token. A personal Gmail account with a sensitive scope shows an "unverified app" screen. Click Advanced, then continue. That screen is Google's, and it is expected.

6. **Service account, if you use one.** Create a service account, download its JSON, and grant it Pub/Sub Subscriber on `ghook-pull` (and Pub/Sub Admin if you want the UI to create the topic). Paste the JSON on **accounts**. This is the default path. See below.

### Which credentials

**Service account for Pub/Sub, OAuth for Gmail.** A pull consumer should not depend on the Gmail refresh token. The mailbox token reads mail and renews the watch. The service account only pulls and acks. If the Gmail token is briefly invalid, queued notifications wait in Pub/Sub instead of taking the consumer down with them.

**OAuth with the Pub/Sub scope** is the other path. Tick it in the wizard and connect again. The signed-in Google user must be allowed to pull the subscription. Use this when you would rather not create a service account. If both are set, the service account wins.

Push mode is optional. Google POSTs to `/hooks/pubsub` with an OIDC JWT. Ghook checks the signature and the audience (the push URL, unless you set another). Set the subscription to push in Cloud Console and switch the mode in the UI. Pull stays the thing to run.

## Label convention

You do not need a route for every destination.

1. On **settings**, leave the prefix at `Ghook` and the convention on.
2. In Gmail, create a label `Ghook/CFO` (the UI can create it when `gmail.modify` is granted).
3. Create a target named `CFO`.
4. A filter, or you by hand, puts that label on the mail that the CFO bot should see.

Ghook delivers it to `CFO` with no rule. `Ghook/Routed/CFO` is the label ghook writes after a route opts in, and it does not itself route. A route can still match the same message; the same target is not posted twice.

A fallback route is the catch-all. Mark it fallback, filter it (category Primary is the useful one), and point it at the bot that should see important mail nobody else claimed.

## Routes

Ordered. The first match wins unless the route says **continue**. A fallback runs only when nothing else matched, and its filter still applies.

| Field | Match |
| --- | --- |
| From, To, Cc | Address (`ada@example.com`) or domain (`example.com`, `@example.com`). A list is OR. |
| Subject | Regular expression. `(?i)` for case insensitive. A broken expression matches nothing. |
| Contains | Case-insensitive, in the snippet or the body. |
| Labels | Any listed label. Names, or system ids such as `INBOX`. |
| Category | primary, social, promotions, updates, forums. |
| Attachment | has one, or has none. |
| Combine | AND or OR across those fields. An empty filter matches everything. |

The simulator runs the rules against the last stored messages before you rely on them. When the mailbox is connected it re-reads the body for the match and does not keep it.

Drag a row to reorder, or focus it and press Alt+Up / Alt+Down. Up and Down buttons do the same without a pointer.

## Targets and delivery

A target is a name, a URL, and a secret.

| Auth | What is sent |
| --- | --- |
| Bearer (default) | `Authorization: Bearer <secret>` |
| Header | the header name you set, value is the secret |
| HMAC | `X-Ghook-Signature: sha256=<hex>` over the raw body |

Every POST also sends `X-Ghook-Delivery`. **Retry** keeps that id so the receiver can dedupe. **Replay** mints a new one so the receiver treats it as new. A window replay (a route, a target, a since/until) does the same for every matching row.

**Grok bot preset:** on the target form, paste `URL KEY` (one space) and press **Fill fields**.

The default payload is metadata. No body, no attachments:

```json
{
  "source": "ghook",
  "route": "primary",
  "account": "ada@example.com",
  "message_id": "18c0...",
  "thread_id": "18c0...",
  "from": "Ada Lovelace <ada@example.com>",
  "to": "ceo@example.com",
  "subject": "Invoice 1042",
  "date": "2026-04-01T12:00:00Z",
  "labels": ["INBOX"],
  "category": "primary",
  "snippet": "please pay the invoice",
  "gmail_url": "https://mail.google.com/mail/u/0/#all/18c0...",
  "delivery_id": "gh_..."
}
```

Tick **include the plain-text body** on a target to add `body` and `body_text`. That text is fetched at send time and, by default, redacted out of the delivery log. A payload template is a Go template over those fields (`{{.Subject}}`, `{{.Body}}`, …). Leave it empty for the JSON above.

A digest time (`08:00` in the display timezone) holds the day's matches and POSTs one body:

```json
{"source":"ghook","digest":true,"target":"CFO","count":2,"items":[ { "...": "..." } ]}
```

Quiet hours (`22:00`–`07:00`, including a window that crosses midnight) wait until the window ends. A per-target rate limit spaces sends. Pause holds the queue. After the attempt limit or the age limit the row is dead, and the notify target (if you set one) gets a short JSON notice with no message body.

The outbox retries with exponential backoff. The base, the cap, the attempt limit and the age limit are on **settings**.

## Admin sign-in

`AUTH_MODE` is `oidc`, `proxy`, or `none`. When it is unset, ghook uses OIDC if `OIDC_ISSUER`, `OIDC_CLIENT_ID`, and `OIDC_CLIENT_SECRET` are set, and otherwise `none`.

| Mode | What happens |
| --- | --- |
| `oidc` | Authorization code with PKCE, same as skgate. No local password. |
| `proxy` | Trust `Remote-User`, `Remote-Email`, `Remote-Name`, and `Remote-Groups` (Authelia's forward-auth headers). The names are `AUTH_PROXY_HEADER` and the matching `AUTH_PROXY_*_HEADER` variables. The TCP peer must be in `AUTH_TRUSTED_PROXIES` (default: loopback, RFC1918, and IPv6 unique-local). |
| `none` | One implicit admin. The UI shows a warning until you turn sign-in on. |

A proxy that bypasses auth for LAN and VPN clients sends those requests with no `Remote-User`. Set `PROXY_FALLBACK_USER` (or the same value under members, once an instance admin exists) to the account that should be used then. If the fallback is `admin` and a later request arrives with `Remote-User: admin`, that is the same account. With no fallback and no header, ghook shows a "no identity header" page.

These paths must bypass forward auth. Google's OAuth consent screen fetches the policy pages, Google redirects the browser to the callback, Pub/Sub posts to the hook, and the healthcheck cannot send a proxy session:

- `/privacy`
- `/terms`
- `/healthz`
- `/admin/google/callback`
- `/hooks/pubsub` (and anything under `/hooks/`)

Put `https://ghook.example.com/privacy` and `https://ghook.example.com/terms` on the OAuth consent screen. Both pages are public and do not require a session.

The admin UI keeps the middleware. The callback still requires ghook's own session cookie, which was set before the browser left for Google.

| Variable | |
| --- | --- |
| `AUTH_MODE` | `oidc`, `proxy`, or `none`. Optional. |
| `OIDC_ISSUER` | Issuer URL. Optional unless mode is `oidc`. |
| `OIDC_CLIENT_ID` / `OIDC_CLIENT_SECRET` | Confidential client. |
| `OIDC_REDIRECT_URL` | Defaults to `PUBLIC_URL/admin/oidc/callback`. |
| `OIDC_ALLOWED_EMAILS` / `OIDC_ALLOWED_GROUPS` | Optional. Empty means anyone the provider admits. |
| `AUTH_TRUSTED_PROXIES` | Comma-separated CIDRs. Optional. |
| `PROXY_FALLBACK_USER` | Identity used when a trusted proxy sends no user header. |
| `PUBLIC_URL` | Origin the browser uses, no trailing slash. |
| `LISTEN_ADDR` | Default `:8080`. |
| `DB_PATH` | Default `/data/ghook.db`. |
| `SECRETS_KEY` | Optional. Empty: `/data/secrets.key` is created on first start. |
| `PUID` / `PGID` | Default `1000`. |

The first person to sign in is the instance admin. Everyone else is a member only where they are invited. Roles are owner, editor, and viewer. With one user and one workspace the switcher and the members page stay hidden.

A workspace owns the mailboxes, Pub/Sub connections, targets, routes, deliveries, settings, and audit log. The Google OAuth client is shared, with an optional per-workspace override. Secrets are sealed with a key derived from the instance key for that workspace. An existing database is moved into a workspace named Default on startup.

Sessions are HMAC cookies, 12 hours, `Secure` when `PUBLIC_URL` is https.

## Settings, import, backup

Everything that changes at runtime is a row in SQLite: the Google client, mailbox tokens, Pub/Sub, routes, targets, retention, the label prefix, notifications, the timezone. Secrets are sealed. The UI shows that a secret is saved and lets you replace or clear it. It does not show the value.

**Export** downloads YAML. Secrets are omitted unless you type a passphrase, which seals them in the file with that passphrase (not the server key). **Import** matches on name. A blank secret does not wipe a stored one.

```sh
ghook export > ghook.yaml
ghook export --passphrase 'correct horse' > ghook.yaml
ghook import ghook.yaml --passphrase 'correct horse'
ghook replay --id 12
ghook replay --route primary --since 2026-04-01
ghook healthcheck
```

**Backup** is a copy of `/data`. You need both `ghook.db` and `secrets.key` (or the `SECRETS_KEY` you set). One without the other cannot open the tokens.

Retention defaults to 30 days of metadata. Bodies are not stored. The delivery log keeps the request with the secret masked and, unless you opt in, the body replaced with `[not stored]`.

The audit log records configuration changes (who, what) and never a secret.

## Keyboard

`g` then `d` status, `a` accounts, `r` routes, `t` targets, `l` deliveries, `s` settings, `u` audit. `/` focuses the filter. `?` lists them. Alt+arrow reorders a focused route.

## Operations

| URL | |
| --- | --- |
| `/healthz` | `{"status":"ok"}`. The image healthcheck uses this. |
| `/metrics` | Prometheus text. Queue depth, dead letters, watch expiry, last notification. |
| `/admin/events` | Server-sent activity feed, signed-in only. |
| `/hooks/pubsub` | Optional push receiver. JWT required. |

`/metrics` is unauthenticated so a scraper on the docker network can read it. Do not publish that port.

## Troubleshooting

| Symptom | What to check |
| --- | --- |
| Watch renewal failed | The topic exists, `gmail-api-push@system.gserviceaccount.com` has Publisher, and the refresh token still works. |
| Refresh token dies every week | The consent screen is still in Testing. Publish it to production. |
| "Unverified app" | Expected for a personal Gmail account. Advanced, then continue. |
| History id too old | Normal after a long outage. Ghook lists the resync window and dedupes. The dashboard says so. |
| Pull errors | The service account JSON is the key for the right project, and it has Subscriber on the subscription. |
| Push returns 401 | The audience must be the push URL. The optional email must be the service account Google signs as. |
| Deliveries sit in retry | The target URL, the secret, and quiet hours. The delivery page has the status and the redacted request. |
| A route matches nothing | Run the simulator. An invalid subject regex matches nothing. A fallback only runs when no earlier rule matched. |
| Label `Ghook/CFO` did nothing | The convention is on, a target is named `CFO`, and the label is not under `Ghook/Routed/`. |

## Develop

```sh
go test ./...
go vet ./...
gofmt -l .
```

```sh
PUBLIC_URL=http://localhost:8080 \
OIDC_ISSUER=https://auth.example.com \
OIDC_CLIENT_ID=ghook \
OIDC_CLIENT_SECRET=change-me \
DB_PATH=./data/ghook.db \
go run ./cmd/ghook
```

CI runs `gofmt`, `go vet` and `go test` on every push and pull request. The release workflow builds `linux/amd64` and `linux/arm64`, pushes `ghcr.io/helv-io/ghook` on `v*` tags, and opens a GitHub Release for a stable `vX.Y.Z`. Do not push a tag until you mean to release.

## License

MIT.
