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

type RegistrationTicketRepo struct {
	pool *pgxpool.Pool
}

func NewRegistrationTicketRepo(pool *pgxpool.Pool) *RegistrationTicketRepo {
	return &RegistrationTicketRepo{pool: pool}
}

func (r *RegistrationTicketRepo) Create(ctx context.Context, ticket domain.RegistrationTicket, tokenHash string) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO registration_tickets (token_hash, client_id, expires_at)
		VALUES ($1, $2, $3)
	`, tokenHash, ticket.ClientID, ticket.ExpiresAt)
	return err
}

func (r *RegistrationTicketRepo) Peek(ctx context.Context, tokenHash string, at time.Time) (domain.RegistrationTicket, error) {
	return r.load(ctx, tokenHash, at, false)
}

func (r *RegistrationTicketRepo) Consume(ctx context.Context, tokenHash string, at time.Time) (domain.RegistrationTicket, error) {
	return r.load(ctx, tokenHash, at, true)
}

func (r *RegistrationTicketRepo) load(ctx context.Context, tokenHash string, at time.Time, consume bool) (domain.RegistrationTicket, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return domain.RegistrationTicket{}, err
	}
	defer tx.Rollback(ctx)

	row := tx.QueryRow(ctx, `
		SELECT client_id, expires_at, used_at
		FROM registration_tickets
		WHERE token_hash = $1
		FOR UPDATE
	`, tokenHash)

	var t domain.RegistrationTicket
	var usedAt *time.Time
	err = row.Scan(&t.ClientID, &t.ExpiresAt, &usedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.RegistrationTicket{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.RegistrationTicket{}, err
	}
	t.UsedAt = usedAt
	if usedAt != nil || !at.Before(t.ExpiresAt) {
		return domain.RegistrationTicket{}, domain.ErrInvalidToken
	}
	if consume {
		if _, err := tx.Exec(ctx, `UPDATE registration_tickets SET used_at = $2 WHERE token_hash = $1`, tokenHash, at); err != nil {
			return domain.RegistrationTicket{}, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return domain.RegistrationTicket{}, err
	}
	return t, nil
}

var _ port.RegistrationTicketRepository = (*RegistrationTicketRepo)(nil)
