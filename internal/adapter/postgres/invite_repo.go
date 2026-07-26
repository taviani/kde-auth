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

type InviteRepo struct {
	pool *pgxpool.Pool
}

func NewInviteRepo(pool *pgxpool.Pool) *InviteRepo {
	return &InviteRepo{pool: pool}
}

func (r *InviteRepo) Create(ctx context.Context, invite domain.Invite, tokenHash string) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO invites (token_hash, client_id, email, created_by, expires_at)
		VALUES ($1, $2, $3, $4, $5)
	`, tokenHash, invite.ClientID, invite.Email.String(), nullUserID(invite.CreatedBy), invite.ExpiresAt)
	return err
}

func (r *InviteRepo) ByTokenHash(ctx context.Context, tokenHash string) (domain.Invite, error) {
	row := r.pool.QueryRow(ctx, `
		SELECT id, client_id, email, created_by, expires_at, used_at, revoked_at, created_at
		FROM invites WHERE token_hash = $1
	`, tokenHash)
	return scanInvite(row)
}

func (r *InviteRepo) ListByClient(ctx context.Context, clientID domain.ClientID) ([]domain.Invite, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, client_id, email, created_by, expires_at, used_at, revoked_at, created_at
		FROM invites
		WHERE client_id = $1
		ORDER BY created_at DESC
		LIMIT 200
	`, clientID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Invite
	for rows.Next() {
		inv, err := scanInvite(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, inv)
	}
	return out, rows.Err()
}

func (r *InviteRepo) Consume(ctx context.Context, id string, at time.Time) error {
	tag, err := r.pool.Exec(ctx, `
		UPDATE invites
		SET used_at = $2
		WHERE id = $1 AND used_at IS NULL AND revoked_at IS NULL AND expires_at > $2
	`, id, at)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrInvalidToken
	}
	return nil
}

func (r *InviteRepo) Revoke(ctx context.Context, id string, at time.Time) error {
	tag, err := r.pool.Exec(ctx, `
		UPDATE invites
		SET revoked_at = $2
		WHERE id = $1 AND used_at IS NULL AND revoked_at IS NULL
	`, id, at)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return nil
}

type inviteScanner interface {
	Scan(dest ...any) error
}

func scanInvite(row inviteScanner) (domain.Invite, error) {
	var inv domain.Invite
	var email string
	var createdBy *string
	err := row.Scan(&inv.ID, &inv.ClientID, &email, &createdBy, &inv.ExpiresAt, &inv.UsedAt, &inv.RevokedAt, &inv.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Invite{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.Invite{}, err
	}
	parsed, err := domain.ParseEmail(email)
	if err != nil {
		return domain.Invite{}, err
	}
	inv.Email = parsed
	if createdBy != nil {
		inv.CreatedBy = domain.UserID(*createdBy)
	}
	return inv, nil
}

func nullUserID(id domain.UserID) any {
	if id == "" {
		return nil
	}
	return string(id)
}

var _ port.InviteRepository = (*InviteRepo)(nil)
