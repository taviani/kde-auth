package usecase

import (
	"context"
	"errors"
	"strings"

	"github.com/taviani/kde-auth/internal/domain"
)

func (uc *AdminClients) UpdateRedirectURIs(ctx context.Context, actor domain.User, clientID, rawURIs, androidPackage string) error {
	if !actor.IsAdmin() {
		return domain.ErrForbidden
	}
	clientID = strings.TrimSpace(clientID)
	if clientID == "" {
		return domain.ValidationError{Field: "client_id", Message: "client_id is required"}
	}
	uris, err := domain.ParseRedirectURIList(rawURIs)
	if err != nil {
		return err
	}
	pkg, err := domain.ParseAndroidPackage(androidPackage)
	if err != nil {
		return err
	}
	err = uc.clients.UpdateRedirectURIs(ctx, domain.ClientID(clientID), uris, pkg)
	if errors.Is(err, domain.ErrNotFound) {
		return domain.ValidationError{Field: "client_id", Message: "client not found"}
	}
	return err
}
