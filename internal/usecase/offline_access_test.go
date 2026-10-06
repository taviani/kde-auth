package usecase

import (
	"context"
	"testing"
	"time"

	"github.com/taviani/kde-auth/internal/domain"
	"github.com/taviani/kde-auth/internal/port"
)

type capturingTokens struct {
	refresh []domain.RefreshToken
}

func (m *capturingTokens) CreateAuthorizationCode(context.Context, domain.AuthorizationCode, string) error {
	return nil
}
func (m *capturingTokens) ConsumeAuthorizationCode(context.Context, string, time.Time) (domain.AuthorizationCode, error) {
	return domain.AuthorizationCode{}, domain.ErrNotFound
}
func (m *capturingTokens) CreateRefreshToken(_ context.Context, token domain.RefreshToken, _ string) error {
	m.refresh = append(m.refresh, token)
	return nil
}
func (m *capturingTokens) ConsumeRefreshToken(context.Context, string, time.Time) (domain.RefreshToken, error) {
	return domain.RefreshToken{}, domain.ErrNotFound
}
func (m *capturingTokens) RevokeRefreshToken(context.Context, string, time.Time) error { return nil }
func (m *capturingTokens) RevokeAllRefreshTokensForUser(context.Context, domain.UserID, time.Time) error {
	return nil
}
func (m *capturingTokens) CreateEmailVerificationToken(context.Context, domain.EmailVerificationToken, string) error {
	return nil
}
func (m *capturingTokens) ConsumeEmailVerificationToken(context.Context, string, time.Time) (domain.EmailVerificationToken, error) {
	return domain.EmailVerificationToken{}, domain.ErrNotFound
}
func (m *capturingTokens) CreatePasswordResetToken(context.Context, domain.PasswordResetToken, string) error {
	return nil
}
func (m *capturingTokens) ConsumePasswordResetToken(context.Context, string, time.Time) (domain.PasswordResetToken, error) {
	return domain.PasswordResetToken{}, domain.ErrNotFound
}

type accessIssuer struct{ stubIssuer }

func (accessIssuer) AccessToken(context.Context, port.AccessClaims) (string, error) {
	return "access.jwt", nil
}

func TestIssueTokensRequiresOfflineAccessForRefresh(t *testing.T) {
	now := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	verified := now
	user := domain.User{
		ID:              "user-1",
		Email:           "u@example.com",
		Status:          domain.UserStatusActive,
		EmailVerifiedAt: &verified,
	}
	tokens := &capturingTokens{}
	uc := NewExchangeToken(nil, tokens, nil, stubHasher{}, accessIssuer{stubIssuer{url: "https://auth.example"}}, frozenClock{t: now})

	without, err := uc.issueTokens(context.Background(), user, "app", "openid email")
	if err != nil {
		t.Fatal(err)
	}
	if without.RefreshToken != "" || len(tokens.refresh) != 0 {
		t.Fatalf("expected no refresh without offline_access: %+v created=%d", without, len(tokens.refresh))
	}
	if without.AccessToken == "" || without.Scope != "openid email" {
		t.Fatalf("access: %+v", without)
	}

	with, err := uc.issueTokens(context.Background(), user, "app", "openid email offline_access")
	if err != nil {
		t.Fatal(err)
	}
	if with.RefreshToken == "" || len(tokens.refresh) != 1 {
		t.Fatalf("expected refresh with offline_access: %+v created=%d", with, len(tokens.refresh))
	}
	if tokens.refresh[0].Scope != "openid email offline_access" {
		t.Fatalf("stored scope: %q", tokens.refresh[0].Scope)
	}
}
