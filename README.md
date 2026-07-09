# kde-auth

Shared OIDC authentication service for [kde.fr](https://kde.fr/) projects.

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
| GET/POST | `/register` | Create account |
| GET | `/verify-email?token=` | Confirm email |
| GET/POST | `/login` | Sign in (session cookie) |
| POST | `/logout` | End session |
| GET | `/authorize` | OAuth2 authorization code |
| POST | `/token` | Exchange code / refresh token |
| GET | `/userinfo` | Profile from Bearer JWT |

## Development

```bash
cp .env.example .env
docker compose up -d db
go run ./cmd/server
```

On localhost, JWT keys and OAuth client defaults are generated/seeded automatically. Verification emails are logged to stdout.

### OAuth smoke test

```bash
# 1. Register at http://localhost:3001/register
# 2. Copy verify URL from server logs, open in browser
# 3. Sign in, then open:
http://localhost:3001/authorize?client_id=dept-app&redirect_uri=http://localhost:4322/auth/callback&response_type=code&scope=openid%20email&state=dev
```

## Production

Set on the server `.env` only (never commit):

- `ISSUER=https://auth.kde.fr`
- `JWT_PRIVATE_KEY` / `JWT_PUBLIC_KEY` (RSA PEM)
- `OAUTH_CLIENT_SECRET`, `OAUTH_REDIRECT_URI`
- `COOKIE_SECURE=true`
- `TURNSTILE_SECRET`, `TURNSTILE_SITE_KEY`
- SMTP settings (or keep log mailer for debugging)

## License

MIT
