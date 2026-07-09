package port

import (
	"context"

	"github.com/taviani/kde-auth/internal/domain"
)

type ClientRepository interface {
	ByClientID(ctx context.Context, clientID domain.ClientID) (domain.OAuthClient, error)
	Upsert(ctx context.Context, client domain.OAuthClient) error
}
