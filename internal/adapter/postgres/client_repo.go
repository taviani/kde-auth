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
		SELECT id, client_id, COALESCE(client_secret_hash, ''), name, redirect_uris, access_mode,
		       COALESCE(token_endpoint_auth_method, 'client_secret_post')
		FROM oauth_clients WHERE client_id = $1
	`, clientID)
	return scanClient(row)
}

func (r *ClientRepo) List(ctx context.Context) ([]domain.OAuthClient, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, client_id, COALESCE(client_secret_hash, ''), name, redirect_uris, access_mode,
		       COALESCE(token_endpoint_auth_method, 'client_secret_post')
		FROM oauth_clients
		ORDER BY created_at ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.OAuthClient
	for rows.Next() {
		c, err := scanClient(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (r *ClientRepo) Upsert(ctx context.Context, client domain.OAuthClient) error {
	mode := client.AccessMode
	if mode == "" {
		mode = domain.AccessModePublic
	}
	authMethod := client.TokenEndpointAuthMethod
	if authMethod == "" {
		authMethod = domain.TokenAuthClientSecretPost
	}
	_, err := r.pool.Exec(ctx, `
		INSERT INTO oauth_clients (
			client_id, client_secret_hash, name, redirect_uris, access_mode, token_endpoint_auth_method
		)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (client_id) DO UPDATE
		SET client_secret_hash = EXCLUDED.client_secret_hash,
		    name = EXCLUDED.name,
		    redirect_uris = EXCLUDED.redirect_uris,
		    token_endpoint_auth_method = EXCLUDED.token_endpoint_auth_method
	`, client.ClientID, client.ClientSecretHash.String(), client.Name, client.RedirectURIs, mode, authMethod)
	return err
}

func (r *ClientRepo) UpdateAccessMode(ctx context.Context, clientID domain.ClientID, mode domain.AccessMode) error {
	tag, err := r.pool.Exec(ctx, `
		UPDATE oauth_clients SET access_mode = $2 WHERE client_id = $1
	`, clientID, mode)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrNotFound
	}
	return nil
}

type clientScanner interface {
	Scan(dest ...any) error
}

func scanClient(row clientScanner) (domain.OAuthClient, error) {
	var c domain.OAuthClient
	var mode string
	var authMethod string
	err := row.Scan(&c.ID, &c.ClientID, &c.ClientSecretHash, &c.Name, &c.RedirectURIs, &mode, &authMethod)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.OAuthClient{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.OAuthClient{}, err
	}
	parsed, err := domain.ParseAccessMode(mode)
	if err != nil {
		return domain.OAuthClient{}, err
	}
	c.AccessMode = parsed
	method, err := domain.ParseTokenEndpointAuthMethod(authMethod)
	if err != nil {
		return domain.OAuthClient{}, err
	}
	c.TokenEndpointAuthMethod = method
	return c, nil
}

var _ port.ClientRepository = (*ClientRepo)(nil)
