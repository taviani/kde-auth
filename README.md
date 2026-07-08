# kde-auth

Shared authentication service for [kde.fr](https://kde.fr/) projects.

## Stack

- **Go 1.22**
- [chi](https://github.com/go-chi/chi) — HTTP router
- [pgx](https://github.com/jackc/pgx) — PostgreSQL driver
- Docker Compose for local development

## Status

Minimal scaffold. Auth features (register, OAuth2, JWT, email verification) are planned — not implemented yet.

## Development

```bash
cp .env.example .env
docker-compose up -d db
go mod tidy
go run ./cmd/server
```

Health check: http://localhost:3001/health

## Project layout

```text
cmd/server/          entrypoint
internal/config/     environment config
internal/handler/    HTTP handlers
internal/server/     router setup
migrations/          SQL migrations (pending)
```

## Planned features

- User registration + email verification
- OAuth2 authorization code flow
- OIDC discovery + JWKS
- Multi-client support (one OAuth client per app)
- Bot protection (Turnstile + rate limits)

## License

MIT
