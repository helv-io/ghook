<p align="center"><img src="docs/img/logo.svg" width="72" alt="ghook logo"></p>
<h1 align="center">ghook</h1>

The G in ghook stands for both Gmail and Grok: Gmail push comes in, Grok Bot webhooks go out.

## What it does

ghook is a self-hosted Gmail push router. Gmail `users.watch` publishes new mail to a Pub/Sub topic. ghook pulls that subscription, matches routes, and POSTs a JSON payload to the webhook that should receive it. Pull needs no public URL, so it works behind NAT.

```
Gmail  --users.watch-->  Pub/Sub topic  --pull-->  ghook  --POST-->  webhook
```

## Quick start

You need a Google Cloud OAuth web client and a shared Pub/Sub topic. Anyone who signs in with Google gets their own account, connects their own Gmail mailbox, and creates their own routes and targets.

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
      - GOOGLE_CLIENT_FILE=/run/secrets/google-client.json
      - PUBSUB_SA_FILE=/run/secrets/pubsub-sa.json
      # optional; defaults are gmail-inbox and ghook-pull
      # - PUBSUB_TOPIC=gmail-inbox
      # - PUBSUB_SUBSCRIPTION=ghook-pull
      # - METRICS_TOKEN=change-me
    volumes:
      - ./data:/data
      - ./google-client.json:/run/secrets/google-client.json:ro
      - ./pubsub-sa.json:/run/secrets/pubsub-sa.json:ro
    healthcheck:
      test: ["CMD", "/ghook", "healthcheck"]
      interval: 30s
      timeout: 5s
      retries: 3
```

1. `docker compose up -d`
2. Open `https://ghook.example.com` and sign in with Google. That creates your account and can connect the same mailbox in one consent.
3. On **targets** and **routes**, say where mail goes.

The image is `ghcr.io/helv-io/ghook`. Tags follow the git tag: `vX.Y.Z`, `X.Y.Z`, and `latest`.

`PUBLIC_URL` must be the `https://` address the browser uses. It is the OAuth redirect and the cookie scope. If you put ghook behind a reverse proxy, drop `ports` and point the proxy at container port 8080. The app itself serves `/login`, `/privacy`, `/terms`, and `/healthz`. Everything else requires a ghook session. Do not put a separate SSO proxy in front of those routes.

### Local trial

```sh
docker compose -f docker-compose.quickstart.yml up -d
```

Point `GOOGLE_CLIENT_FILE` and `PUBSUB_SA_FILE` at your local JSON files (see `.env.example`). Open `http://localhost:8080` and sign in with Google. Add `http://localhost:8080/admin/google/callback` as an authorized redirect URI on the OAuth client.

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

**Account.** One Gmail mailbox with a `users.watch` on the topic. ghook stores the history id per mailbox and renews the watch before it expires (about 7 days).

**Target.** A named webhook: a URL and a secret. Auth is Bearer (default), a named header, or HMAC (`X-Ghook-Signature`). Every POST also sends `X-Ghook-Delivery`. On the target form, paste `URL KEY` (one space) and use **Fill fields** for a Grok Bot webhook. A target may also supply an `age1…` public key; ghook then encrypts the outbound body so only the holder of the matching secret can read it.

**Route.** An ordered rule that matches mail and posts to one target. The first match wins unless the route says **continue**. A fallback runs only when nothing else matched, and its filter still applies. Use the simulator against recent mail before you rely on a rule. Sender lists are kept sorted: domains, then `*.` domains, then full addresses. On **routes**, click a value to edit it in place.

| Field | Match |
| --- | --- |
| From, To, Cc | Address (`ada@example.com`) or domain (`example.com`, the apex and every subdomain). `*.capitalone.com` matches subdomains only, not the apex. Case-insensitive. A list is OR. |
| Subject | Regular expression. `(?i)` for case insensitive. A broken expression matches nothing. |
| Contains | Case-insensitive, in the snippet or the body. |
| Labels | Any listed label. Names, or system ids such as `INBOX`. |
| Category | primary, social, promotions, updates, forums. |
| Attachment | has one, or has none. |
| Combine | AND or OR across those fields. An empty filter matches everything. |

**Label convention.** On **settings**, leave the prefix at `ghook` and the convention on. A Gmail label `ghook/CFO` delivers to the target named `CFO` with no route. Existing `Ghook/` labels still match. `ghook/Routed/CFO` is the label ghook writes after a route opts in, and it does not itself route.

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

## Auth and accounts

Sign-in is Google only. Anyone who completes Google sign-in gets their own account. There is no owner, invite list, or allowlist. Each user connects their own Gmail mailbox, and sees only their own routes, targets, deliveries, settings, and audit log.

The Google OAuth client and the Pub/Sub topic are instance-wide, set by the operator through the environment. Users do not paste credentials.

From the **account** page a user can sign out, or delete their account and data: ghook stops the Gmail watch, revokes the Google token, destroys that user's data key (so leftover ciphertext cannot be opened), and deletes the rows.

Per-user defaults: 25 targets, 50 routes, and 1000 deliveries per UTC day (`MAX_TARGETS`, `MAX_ROUTES`, `MAX_DELIVERIES_PER_DAY`).

Public paths served by the app, with no session:

- `/` (redirects to `/login` or `/admin`)
- `/login`, `/privacy`, `/terms`
- `/healthz`
- `/admin/google/callback`
- `/hooks/pubsub` (and anything under `/hooks/`)

`/metrics` is not public. Set `METRICS_TOKEN` and call it with `Authorization: Bearer <token>`. If the token is unset, `/metrics` returns 404. The text is aggregate only: queue counts, user count, active watches. It does not include account emails.

## Data protection

ghook has to process mail in memory to decide which webhook to call. That is not end-to-end encryption. A future option is to run the process in a confidential VM; this version does not.

What the operator of an instance can and cannot see:

- Login and mailbox addresses are stored in the clear. They are the lookup key for the shared Pub/Sub `emailAddress`.
- Delivery logs store metadata (message id, route, target, status, timing). Message bodies and snippets are not written unless you turn body retention on, and even then they are encrypted and purged after the retention window.
- Google tokens, target secrets, any stored payloads, and route match fields are encrypted at rest with a per-user data key (DEK). That DEK is itself wrapped by the instance key (`SECRETS_KEY`, or `/data/secrets.key` if you leave `SECRETS_KEY` empty).
- An operator who has both the database and the instance key can decrypt those fields. A copy of the database file without the instance key cannot.
- If a target has an `age1…` public key, the webhook body is encrypted so that only the receiver can read it. ghook still sees the plaintext in memory before it encrypts the POST.
- Logs redact email addresses and never print secrets. Metrics never include emails.
- Deleting an account shreds the per-user key first, then deletes the rows.

`ghook keys rotate --user ada@example.com` (or `--all`) mints a new data key and re-seals that user's secrets. `ghook keys rotate-kek` re-wraps every data key and swaps the key file. It only works with a key file (`SECRETS_KEY` must be unset). The previous file is kept as `secrets.key.bak`. Neither command prints key material.

## Environment

Required to boot a typical deploy. Routes, targets and retention still live in the database, per user.

| Variable | |
| --- | --- |
| `PUBLIC_URL` | Origin the browser uses, no trailing slash. |
| `GOOGLE_CLIENT_FILE` or `GOOGLE_CLIENT_JSON` | Web OAuth client JSON. |
| `PUBSUB_SA_FILE` or `PUBSUB_SA_JSON` | Service account that can pull the shared subscription. |

Defaults: `LISTEN_ADDR=:8080`, `DB_PATH=/data/ghook.db`, topic `gmail-inbox`, subscription `ghook-pull`. `PUBSUB_PROJECT` is read from the service account JSON when unset. If `SECRETS_KEY` is empty, `/data/secrets.key` is created on first start. That file is the instance key that wraps every per-user data key; prefer the file over `SECRETS_KEY` if you want to run `ghook keys rotate-kek`. Optional variables are in [AGENT.md](AGENT.md) and `.env.example`.

A v0.1.3 database is opened and migrated in place. Do not replace the data directory when upgrading from 0.1.3 to 0.1.4. Opening a pre-0.1.3 file (workspace-era schema) still returns an error asking you to back up and replace it.

## Operations

| URL | |
| --- | --- |
| `/healthz` | `{"status":"ok"}`. The image healthcheck uses this. |
| `/metrics` | Prometheus text: queue depth, dead letters, user count, active watches, database size and last compaction. Requires `METRICS_TOKEN`. Aggregate only; no account emails. |
| `/hooks/pubsub` | Optional push receiver. JWT required. |

**Compaction** runs every day at 03:15 local time (`TZ`). It purges rows past the retention window, truncates the WAL and returns free pages to the disk. Set `COMPACT_AT=HH:MM` to move it or `COMPACT_AT=off` to turn it off. A file that is mostly free space is also compacted about 30 seconds after start. `ghook compact` does the same by hand.

**Backup** is a copy of `/data`. You need both `ghook.db` and `secrets.key` (or the `SECRETS_KEY` you set). One without the other cannot open tokens or sealed payloads. To upgrade, copy `./data` somewhere safe, then `docker compose pull && docker compose up -d`.

The CLI talks to the same database:

```sh
ghook healthcheck
ghook export --user ada@example.com > ghook.yaml
ghook export --user ada@example.com --passphrase 'correct horse' > ghook.yaml
ghook import --user ada@example.com ghook.yaml --passphrase 'correct horse'
ghook replay --user ada@example.com --id 12
ghook replay --user ada@example.com --route primary --since 2026-04-01
ghook keys rotate --user ada@example.com
ghook keys rotate --all
ghook keys rotate-kek
```

Export omits secrets unless you set a passphrase, which seals them in the file. Import matches on name. A blank secret does not wipe a stored one. **Retry** in the UI keeps the delivery id. **Replay** (UI or CLI) mints a new one.

## Troubleshooting

| Symptom | What to check |
| --- | --- |
| Watch renewal failed | The topic exists, `gmail-api-push@system.gserviceaccount.com` has Publisher, and the refresh token still works. |
| Refresh token dies every week | The consent screen is still in Testing. Publish it to production. |
| "Unverified app" | Expected for a personal Gmail account. Advanced, then continue. |
| History id too old | Normal after a long outage. ghook lists the resync window and dedupes. The dashboard says so. |
| Pull errors | The service account JSON is the key for the right project, and it has Subscriber on the subscription. |
| Push returns 401 | The audience must be the push URL. The optional email must be the service account Google signs as. |
| Deliveries sit in retry | The target URL, the secret, and quiet hours. The delivery page has the status and the redacted request. |
| A route matches nothing | Run the simulator. An invalid subject regex matches nothing. A fallback only runs when no earlier rule matched. |
| Label `ghook/CFO` did nothing | The convention is on, a target is named `CFO`, and the label is not under `ghook/Routed/`. Existing `Ghook/` labels also match. |

## License

MIT, see [LICENSE](LICENSE).

Contributors and agents: [AGENT.md](AGENT.md).
