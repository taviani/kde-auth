package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/taviani/kde-auth/internal/domain"
	"github.com/taviani/kde-auth/internal/port"
)

type ClientRepo struct {
	pool *pgxpool.Pool
}

func NewClientRepo(pool *pgxpool.Pool) *ClientRepo {
	return &ClientRepo{pool: pool}
}

func (r *ClientRepo) ByClientID(ctx context.Context, clientID domain.ClientID) (domain.OAuthClient, error) {
	row := r.pool.QueryRow(ctx, `
		SELECT id, client_id, client_secret_hash, name, redirect_uris
		FROM oauth_clients WHERE client_id = $1
	`, clientID)

	var c domain.OAuthClient
	err := row.Scan(&c.ID, &c.ClientID, &c.ClientSecretHash, &c.Name, &c.RedirectURIs)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.OAuthClient{}, domain.ErrNotFound
	}
	return c, err
}

func (r *ClientRepo) Upsert(ctx context.Context, client domain.OAuthClient) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO oauth_clients (client_id, client_secret_hash, name, redirect_uris)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (client_id) DO UPDATE
		SET client_secret_hash = EXCLUDED.client_secret_hash,
		    name = EXCLUDED.name,
		    redirect_uris = EXCLUDED.redirect_uris
	`, client.ClientID, client.ClientSecretHash.String(), client.Name, client.RedirectURIs)
	return err
}

var _ port.ClientRepository = (*ClientRepo)(nil)
