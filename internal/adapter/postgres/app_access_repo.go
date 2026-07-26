package postgres

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/taviani/kde-auth/internal/domain"
	"github.com/taviani/kde-auth/internal/port"
)

type AppAccessRepo struct {
	pool *pgxpool.Pool
}

func NewAppAccessRepo(pool *pgxpool.Pool) *AppAccessRepo {
	return &AppAccessRepo{pool: pool}
}

func (r *AppAccessRepo) Upsert(ctx context.Context, access domain.UserAppAccess) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO user_app_accesses (user_id, client_id, entry_domain, first_seen_at, last_seen_at)
		VALUES ($1, $2, $3, $4, $4)
		ON CONFLICT (user_id, client_id) DO UPDATE SET
			last_seen_at = EXCLUDED.last_seen_at,
			entry_domain = CASE
				WHEN EXCLUDED.entry_domain <> '' THEN EXCLUDED.entry_domain
				ELSE user_app_accesses.entry_domain
			END
	`, access.UserID, access.ClientID, access.EntryDomain, access.LastSeenAt)
	return err
}

func (r *AppAccessRepo) HasAccess(ctx context.Context, userID domain.UserID, clientID domain.ClientID) (bool, error) {
	var exists bool
	err := r.pool.QueryRow(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM user_app_accesses WHERE user_id = $1 AND client_id = $2
		)
	`, userID, clientID).Scan(&exists)
	return exists, err
}

var _ port.AppAccessRepository = (*AppAccessRepo)(nil)
