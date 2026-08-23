# Auth service

Shared OIDC authentication service for your projects.

## Stack

- **Go 1.25** — chi router, pgx, stdlib-first
- **PostgreSQL** — plain SQL migrations
- **RS256 JWT** — JWKS for API verification
- Docker Compose for local development

## Architecture

```text
cmd/server/           composition root
internal/domain/      entities, value objects, rules
internal/port/        driven interfaces
internal/usecase/     application services
internal/adapter/     http, postgres, crypto, mail
```

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Liveness |
| GET | `/.well-known/openid-configuration` | OIDC discovery |
| GET | `/jwks` | Public signing keys |
| POST | `/register/ticket` | Confidential client (`client_id` + `client_secret`) mints a one-time registration ticket |
| GET/POST | `/register` | Create account (**requires** `ticket`; otherwise 404) |
| GET | `/verify-email?token=` | Confirm email |
| GET/POST | `/login` | Sign in (session cookie). Rate-limited. No public register link. |
| POST | `/logout` | End session |
| GET | `/authorize` | OAuth2 authorization code (supports PKCE `S256`) |
| POST | `/token` | Exchange code / refresh token |
| GET | `/invite` | Accept an invite (invite-only apps) |

`GET /` is **404**. `/admin` is **404** unless the session is an admin (no login redirect).

Public (mobile) clients use `token_endpoint_auth_method=none` and **must** send PKCE (`code_challenge` / `code_verifier`). They cannot mint registration tickets. Confidential clients keep `client_secret_post` (PKCE optional) and may mint tickets only when `access_mode=public`.

Invite-only apps never use `/register` — issue an invite in admin instead.

Supported scopes: `openid` (required), `email`, `offline_access` (native apps that store a refresh token).

Public (mobile) clients use `token_endpoint_auth_method=none` and **must** send PKCE (`code_challenge` / `code_verifier`). Confidential clients keep `client_secret_post` (PKCE optional).

Supported scopes: `openid` (required), `email`, `offline_access` (native apps that store a refresh token).

| GET | `/userinfo` | Profile from Bearer JWT |
| POST | `/account/password` | Change password (Bearer JWT; body: `current_password`, `new_password`, `new_password_confirm`) |

## Development

```bash
cp .env.example .env
docker compose up -d db
go run ./cmd/server
```

On localhost, JWT keys and OAuth client defaults are generated/seeded automatically. Verification emails are logged to stdout.

### OAuth smoke test

```bash
# 1. Mint a registration ticket (confidential client + secret from .env)
curl -sS -X POST http://localhost:3001/register/ticket \
  -d client_id=auth-test \
  -d client_secret=dev-secret-change-me-16
# 2. Open the returned register_url, create the account
# 3. Copy verify URL from server logs, open in browser
# 4. Sign in, then open:
http://localhost:3001/authorize?client_id=auth-test&redirect_uri=http://localhost:4322/auth/callback&response_type=code&scope=openid%20email%20offline_access&state=dev
```

### Native app redirect (`app://`, custom schemes)

After `/authorize`, custom-scheme redirect URIs return a **200 HTML page** with an **Open app** button (instead of an HTTP 302 that Chrome shows as “Found”).

On **Android** (Chrome Custom Tabs), the button uses an `intent://…#Intent;scheme=…;package=…;end` link when the OAuth client has `android_package` set. **iOS** keeps the original custom-scheme URL.

Set the Play package on the server (not in git):

```sql
UPDATE oauth_clients SET android_package = 'com.your.app' WHERE client_id = 'your-client-id';
```

## Production

Set on the server `.env` only (never commit):

- `ISSUER=https://auth.example.com` (your public auth URL)
- `JWT_PRIVATE_KEY` / `JWT_PUBLIC_KEY` (RSA PEM) or `JWT_*_FILE`
- `OAUTH_CLIENT_SECRET`, `OAUTH_REDIRECT_URI`
- `COOKIE_SECURE=true`
- `TURNSTILE_SECRET`, `TURNSTILE_SITE_KEY` (**required** in production)
- SMTP settings (or keep log mailer for debugging)

## License

MIT
