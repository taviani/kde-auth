package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/taviani/kde-auth/internal/domain"
	"github.com/taviani/kde-auth/internal/port"
)

type SessionRepo struct {
	pool *pgxpool.Pool
}

func NewSessionRepo(pool *pgxpool.Pool) *SessionRepo {
	return &SessionRepo{pool: pool}
}

func (r *SessionRepo) Create(ctx context.Context, session domain.Session, tokenHash string) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO sessions (id, token_hash, user_id, expires_at)
		VALUES ($1, $2, $3, $4)
	`, session.ID, tokenHash, session.UserID, session.ExpiresAt)
	return err
}

func (r *SessionRepo) ByTokenHash(ctx context.Context, tokenHash string, at time.Time) (domain.Session, error) {
	row := r.pool.QueryRow(ctx, `
		SELECT id, user_id, expires_at
		FROM sessions
		WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > $2
	`, tokenHash, at)

	var s domain.Session
	err := row.Scan(&s.ID, &s.UserID, &s.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Session{}, domain.ErrNotFound
	}
	return s, err
}

func (r *SessionRepo) Revoke(ctx context.Context, tokenHash string, at time.Time) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE sessions SET revoked_at = $2 WHERE token_hash = $1 AND revoked_at IS NULL
	`, tokenHash, at)
	return err
}

var _ port.SessionRepository = (*SessionRepo)(nil)
