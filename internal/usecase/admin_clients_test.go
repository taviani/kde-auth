package usecase

import (
	"context"
	"errors"
	"testing"

	"github.com/taviani/kde-auth/internal/domain"
)

func TestUpdateRedirectURIsReplacesTheList(t *testing.T) {
	repo := &memClients{byID: map[domain.ClientID]domain.OAuthClient{
		"app": {
			ClientID:                "app",
			Name:                    "App",
			ClientSecretHash:        "hash",
			RedirectURIs:            []string{"https://old.example/cb"},
			AccessMode:              domain.AccessModeInviteOnly,
			TokenEndpointAuthMethod: domain.TokenAuthClientSecretPost,
			AndroidPackage:          "com.example.app",
		},
	}}
	uc := NewAdminClients(repo, nil)
	admin := domain.User{Role: domain.RoleAdmin}

	err := uc.UpdateRedirectURIs(context.Background(), admin, " app ", "https://new.example/cb\napp://cb", " com.other.app ")
	if err != nil {
		t.Fatal(err)
	}
	got := repo.byID["app"]
	if len(got.RedirectURIs) != 2 || got.RedirectURIs[0] != "https://new.example/cb" || got.RedirectURIs[1] != "app://cb" {
		t.Fatalf("uris = %#v", got.RedirectURIs)
	}
	if got.AndroidPackage != "com.other.app" {
		t.Fatalf("package = %q", got.AndroidPackage)
	}
	if got.Name != "App" || got.ClientSecretHash != "hash" || got.AccessMode != domain.AccessModeInviteOnly {
		t.Fatalf("other fields changed: %#v", got)
	}

	if err := uc.UpdateRedirectURIs(context.Background(), admin, "app", "app://cb", "  "); err != nil {
		t.Fatal(err)
	}
	if repo.byID["app"].AndroidPackage != "" {
		t.Fatalf("package = %q", repo.byID["app"].AndroidPackage)
	}
}

func TestUpdateRedirectURIsRejectsNonAdminAndInvalidInput(t *testing.T) {
	repo := &memClients{byID: map[domain.ClientID]domain.OAuthClient{
		"app": {ClientID: "app", RedirectURIs: []string{"https://old.example/cb"}},
	}}
	uc := NewAdminClients(repo, nil)
	ctx := context.Background()

	if err := uc.UpdateRedirectURIs(ctx, domain.User{}, "app", "https://new.example/cb", ""); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("non-admin: %v", err)
	}
	if got := repo.byID["app"].RedirectURIs; len(got) != 1 || got[0] != "https://old.example/cb" {
		t.Fatalf("uris changed: %#v", got)
	}

	admin := domain.User{Role: domain.RoleAdmin}
	if err := uc.UpdateRedirectURIs(ctx, admin, "app", " \n", ""); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("empty: %v", err)
	}
	if err := uc.UpdateRedirectURIs(ctx, admin, "app", "app://cb", "not a package"); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("package: %v", err)
	}
	if err := uc.UpdateRedirectURIs(ctx, admin, "app", "intent://callback#Intent;scheme=app;package=com.example.app;end", "com.example.app"); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("intent uri: %v", err)
	}
	if err := uc.UpdateRedirectURIs(ctx, admin, "missing", "https://new.example/cb", ""); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("missing: %v", err)
	}
	if got := repo.byID["app"].RedirectURIs; len(got) != 1 || got[0] != "https://old.example/cb" {
		t.Fatalf("uris changed: %#v", got)
	}
}
