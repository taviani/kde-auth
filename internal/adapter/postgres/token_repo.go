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

type TokenRepo struct {
	pool *pgxpool.Pool
}

func NewTokenRepo(pool *pgxpool.Pool) *TokenRepo {
	return &TokenRepo{pool: pool}
}

func (r *TokenRepo) CreateAuthorizationCode(ctx context.Context, code domain.AuthorizationCode, codeHash string) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO authorization_codes (code_hash, user_id, client_id, redirect_uri, scope, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, codeHash, code.UserID, code.ClientID, code.RedirectURI, code.Scope, code.ExpiresAt)
	return err
}

func (r *TokenRepo) ConsumeAuthorizationCode(ctx context.Context, codeHash string, at time.Time) (domain.AuthorizationCode, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return domain.AuthorizationCode{}, err
	}
	defer tx.Rollback(ctx)

	row := tx.QueryRow(ctx, `
		SELECT user_id, client_id, redirect_uri, scope, expires_at, used_at
		FROM authorization_codes
		WHERE code_hash = $1
		FOR UPDATE
	`, codeHash)

	var c domain.AuthorizationCode
	var usedAt *time.Time
	err = row.Scan(&c.UserID, &c.ClientID, &c.RedirectURI, &c.Scope, &c.ExpiresAt, &usedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.AuthorizationCode{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.AuthorizationCode{}, err
	}
	if usedAt != nil || !at.Before(c.ExpiresAt) {
		return domain.AuthorizationCode{}, domain.ErrInvalidGrant
	}

	if _, err := tx.Exec(ctx, `UPDATE authorization_codes SET used_at = $2 WHERE code_hash = $1`, codeHash, at); err != nil {
		return domain.AuthorizationCode{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.AuthorizationCode{}, err
	}
	return c, nil
}

func (r *TokenRepo) CreateRefreshToken(ctx context.Context, token domain.RefreshToken, tokenHash string) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO refresh_tokens (token_hash, user_id, client_id, expires_at)
		VALUES ($1, $2, $3, $4)
	`, tokenHash, token.UserID, token.ClientID, token.ExpiresAt)
	return err
}

func (r *TokenRepo) ConsumeRefreshToken(ctx context.Context, tokenHash string, at time.Time) (domain.RefreshToken, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return domain.RefreshToken{}, err
	}
	defer tx.Rollback(ctx)

	row := tx.QueryRow(ctx, `
		SELECT user_id, client_id, expires_at, revoked_at
		FROM refresh_tokens
		WHERE token_hash = $1
		FOR UPDATE
	`, tokenHash)

	var t domain.RefreshToken
	var revokedAt *time.Time
	err = row.Scan(&t.UserID, &t.ClientID, &t.ExpiresAt, &revokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.RefreshToken{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.RefreshToken{}, err
	}
	if revokedAt != nil || !at.Before(t.ExpiresAt) {
		return domain.RefreshToken{}, domain.ErrInvalidGrant
	}

	if _, err := tx.Exec(ctx, `UPDATE refresh_tokens SET revoked_at = $2 WHERE token_hash = $1`, tokenHash, at); err != nil {
		return domain.RefreshToken{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.RefreshToken{}, err
	}
	return t, nil
}

func (r *TokenRepo) RevokeRefreshToken(ctx context.Context, tokenHash string, at time.Time) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE refresh_tokens SET revoked_at = $2 WHERE token_hash = $1 AND revoked_at IS NULL
	`, tokenHash, at)
	return err
}

func (r *TokenRepo) CreateEmailVerificationToken(ctx context.Context, token domain.EmailVerificationToken, tokenHash string) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO email_verification_tokens (token_hash, user_id, expires_at)
		VALUES ($1, $2, $3)
	`, tokenHash, token.UserID, token.ExpiresAt)
	return err
}

func (r *TokenRepo) ConsumeEmailVerificationToken(ctx context.Context, tokenHash string, at time.Time) (domain.EmailVerificationToken, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return domain.EmailVerificationToken{}, err
	}
	defer tx.Rollback(ctx)

	row := tx.QueryRow(ctx, `
		SELECT user_id, expires_at, used_at
		FROM email_verification_tokens
		WHERE token_hash = $1
		FOR UPDATE
	`, tokenHash)

	var t domain.EmailVerificationToken
	var usedAt *time.Time
	err = row.Scan(&t.UserID, &t.ExpiresAt, &usedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.EmailVerificationToken{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.EmailVerificationToken{}, err
	}
	if usedAt != nil || !at.Before(t.ExpiresAt) {
		return domain.EmailVerificationToken{}, domain.ErrInvalidToken
	}

	if _, err := tx.Exec(ctx, `UPDATE email_verification_tokens SET used_at = $2 WHERE token_hash = $1`, tokenHash, at); err != nil {
		return domain.EmailVerificationToken{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.EmailVerificationToken{}, err
	}
	return t, nil
}

var _ port.TokenRepository = (*TokenRepo)(nil)
