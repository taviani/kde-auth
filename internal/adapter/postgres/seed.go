package postgres

import (
	"context"

	"github.com/taviani/kde-auth/internal/domain"
	"github.com/taviani/kde-auth/internal/port"
)

type Seed struct {
	clients port.ClientRepository
	hasher  port.PasswordHasher
}

func NewSeed(clients port.ClientRepository, hasher port.PasswordHasher) *Seed {
	return &Seed{clients: clients, hasher: hasher}
}

type OAuthClientSeed struct {
	ClientID     string
	ClientSecret string
	Name         string
	RedirectURI  string
}

func (s *Seed) OAuthClient(ctx context.Context, in OAuthClientSeed) error {
	secretHash, err := s.hasher.Hash(ctx, domain.PlainPassword(in.ClientSecret))
	if err != nil {
		return err
	}
	return s.clients.Upsert(ctx, domain.OAuthClient{
		ClientID:         domain.ClientID(in.ClientID),
		ClientSecretHash: secretHash,
		Name:             in.Name,
		RedirectURIs:     []string{in.RedirectURI},
	})
}
