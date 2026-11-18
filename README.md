<p align="center"><img src="docs/img/logo.svg" width="72" alt="ghook logo"></p>
<h1 align="center">ghook</h1>

The G in Ghook stands for both Gmail and Grok: Gmail push comes in, Grok Bot webhooks go out.

## What it does

Ghook is a self-hosted Gmail push router. Gmail `users.watch` publishes new mail to a Pub/Sub topic. Ghook pulls that subscription, matches routes, and POSTs a JSON payload to the webhook that should receive it. Pull needs no public URL, so it works behind NAT.

```
Gmail  --users.watch-->  Pub/Sub topic  --pull-->  ghook  --POST-->  webhook
```

## Quick start

You need an [OIDC provider](#auth-and-workspaces) with a confidential client. To try it on one machine with no provider of your own, use `docker-compose.quickstart.yml`.

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
3. On **accounts**, paste the Google OAuth client, connect a mailbox, and set the Pub/Sub topic.
4. On **targets** and **routes**, say where mail goes.

The image is `ghcr.io/helv-io/ghook`. Tags follow the git tag: `vX.Y.Z`, `X.Y.Z`, and `latest`.

`PUBLIC_URL` must be the `https://` address the browser uses. It is the OAuth redirect and the cookie scope. If you put ghook behind a reverse proxy, drop `ports` and point the proxy at container port 8080.

### One machine, no identity provider

```sh
docker compose -f docker-compose.quickstart.yml up -d
```

Open `http://localhost:8080/admin`. Sign in as `admin@example.com` / `password`. The login, the client secret, and plain HTTP are public knowledge. Do not expose this compose file. Configure Google in the UI afterwards.

## Google setup

Do this once per Google Cloud project.

1. Create a project and enable the Gmail API and the Cloud Pub/Sub API.
2. Create a topic and let Gmail publish to it:
   ```sh
   gcloud pubsub topics create ghook
   gcloud pubsub topics add-iam-policy-binding ghook \
     --member=serviceAccount:gmail-api-push@system.gserviceaccount.com \
     --role=roles/pubsub.publisher
   ```
   The UI can create the topic and grant publish after you save credentials.
3. Create a pull subscription. Use a 60 second ack deadline, 7 day retention, and no expiration:
   ```sh
   gcloud pubsub subscriptions create ghook-pull --topic=ghook \
     --ack-deadline=60 \
     --message-retention-duration=7d \
     --expiration-period=never
   ```
4. Create an OAuth consent screen (External) and a Web application client. Authorized redirect URI is `PUBLIC_URL` plus `/admin/google/callback`, for example `https://ghook.example.com/admin/google/callback`. The default scope is `gmail.readonly`. Add `gmail.modify` only if ghook should apply labels, and `gmail.settings.basic` only if it should create filters. Download the client JSON and paste it on **accounts**.
5. Publish the consent screen to production. A screen left in Testing expires refresh tokens after 7 days, and the watch dies with them. A personal Gmail account with a sensitive scope shows an unverified-app screen. Click Advanced, then continue. That screen is Google's, and it is expected.
6. For Pub/Sub, create a service account, grant it Pub/Sub Subscriber on `ghook-pull`, and paste its JSON on **accounts**. This is the default path. The Gmail OAuth token reads mail and renews the watch. The service account only pulls and acks, so a briefly invalid Gmail token does not take the consumer down.

The other path is to tick the Pub/Sub scope in the wizard and connect again, when the signed-in Google user can pull the subscription and you would rather not create a service account. If both are set, the service account is used.

Push mode is optional. Google POSTs to `/hooks/pubsub` with an OIDC JWT. Pull is what you should run.

## Concepts

**Account.** One Gmail mailbox with a `users.watch` on the topic. Ghook stores the history id per mailbox and renews the watch before it expires (about 7 days).

**Target.** A named webhook: a URL and a secret. Auth is Bearer (default), a named header, or HMAC (`X-Ghook-Signature`). Every POST also sends `X-Ghook-Delivery`. On the target form, paste `URL KEY` (one space) and use **Fill fields** for a Grok Bot webhook.

**Route.** An ordered rule that matches mail and posts to one target. The first match wins unless the route says **continue**. A fallback runs only when nothing else matched, and its filter still applies. Use the simulator against recent mail before you rely on a rule.

| Field | Match |
| --- | --- |
| From, To, Cc | Address (`ada@example.com`) or domain (`example.com`). A list is OR. |
| Subject | Regular expression. `(?i)` for case insensitive. A broken expression matches nothing. |
| Contains | Case-insensitive, in the snippet or the body. |
| Labels | Any listed label. Names, or system ids such as `INBOX`. |
| Category | primary, social, promotions, updates, forums. |
| Attachment | has one, or has none. |
| Combine | AND or OR across those fields. An empty filter matches everything. |

**Label convention.** On **settings**, leave the prefix at `Ghook` and the convention on. A Gmail label `Ghook/CFO` delivers to the target named `CFO` with no route. `Ghook/Routed/CFO` is the label ghook writes after a route opts in, and it does not itself route.

**Deliveries.** Each match is an outbox row. Retry keeps the same `X-Ghook-Delivery` id so the receiver can dedupe. Replay mints a new id. The outbox uses exponential backoff. After the attempt limit or the age limit the row is dead. Quiet hours, a digest time, a per-target rate limit, and pause are set on the target. Retry limits are on **settings**.

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

Tick **include the plain-text body** on a target to add `body` and `body_text`. A payload template is a Go template over those fields. Leave it empty for the JSON above.

## Auth and workspaces

`AUTH_MODE` is `oidc`, `proxy`, or `none`. When it is unset, ghook uses OIDC if `OIDC_ISSUER`, `OIDC_CLIENT_ID`, and `OIDC_CLIENT_SECRET` are set, and otherwise `none`.

| Mode | What happens |
| --- | --- |
| `oidc` | Authorization code with PKCE. No local password. |
| `proxy` | Trust `Remote-User`, `Remote-Email`, `Remote-Name`, and `Remote-Groups` (the Authelia and Authentik forward-auth headers). The TCP peer must be in `AUTH_TRUSTED_PROXIES`. |
| `none` | One implicit admin. The UI shows a warning until you turn sign-in on. |

If a trusted proxy sends no `Remote-User`, set `PROXY_FALLBACK_USER` to the account that should be used. With no fallback and no header, ghook shows a "no identity header" page.

These paths must bypass forward auth:

- `/privacy`, `/terms` (put these URLs on the OAuth consent screen)
- `/healthz`
- `/admin/google/callback`
- `/hooks/pubsub` (and anything under `/hooks/`)

The admin UI stays behind the proxy. The Google callback still requires ghook's own session cookie, which was set before the browser left for Google.

The first person to sign in is the instance admin. Everyone else is a member only where they are invited. Roles are owner, editor, and viewer.

A workspace owns the mailboxes, Pub/Sub connections, targets, routes, deliveries, settings, and audit log. The Google OAuth client is shared, with an optional per-workspace override. Secrets are sealed with a key derived from the instance key for that workspace.

## Environment

Required to boot a typical deploy. Everything else (Google, routes, targets, retention) lives in the database.

| Variable | |
| --- | --- |
| `PUBLIC_URL` | Origin the browser uses, no trailing slash. |
| `AUTH_MODE` | `oidc`, `proxy`, or `none`. Optional. Unset: OIDC if the three variables below are set, otherwise `none`. |
| `OIDC_ISSUER` | Issuer URL. Required when mode is `oidc`. |
| `OIDC_CLIENT_ID` | Confidential client id. Required when mode is `oidc`. |
| `OIDC_CLIENT_SECRET` | Confidential client secret. Required when mode is `oidc`. |

Defaults: `LISTEN_ADDR=:8080`, `DB_PATH=/data/ghook.db`. If `SECRETS_KEY` is empty, `/data/secrets.key` is created on first start. Optional auth variables are in [AGENT.md](AGENT.md).

## Operations

| URL | |
| --- | --- |
| `/healthz` | `{"status":"ok"}`. The image healthcheck uses this. |
| `/metrics` | Prometheus text: queue depth, dead letters, watch expiry, last notification. Unauthenticated. Do not publish that port. |
| `/hooks/pubsub` | Optional push receiver. JWT required. |

**Backup** is a copy of `/data`. You need both `ghook.db` and `secrets.key` (or the `SECRETS_KEY` you set). One without the other cannot open the tokens. To upgrade, copy `./data` somewhere safe, then `docker compose pull && docker compose up -d`.

The CLI talks to the same database:

```sh
ghook healthcheck
ghook export > ghook.yaml
ghook export --passphrase 'correct horse' > ghook.yaml
ghook import ghook.yaml --passphrase 'correct horse'
ghook replay --id 12
ghook replay --route primary --since 2026-04-01
```

Export omits secrets unless you set a passphrase, which seals them in the file. Import matches on name. A blank secret does not wipe a stored one. **Retry** in the UI keeps the delivery id. **Replay** (UI or CLI) mints a new one.

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

## License

MIT, see [LICENSE](LICENSE).

Contributors and agents: [AGENT.md](AGENT.md).
