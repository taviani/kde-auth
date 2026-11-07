package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/taviani/kde-auth/internal/adapter/http/response"
	"github.com/taviani/kde-auth/internal/domain"
	"github.com/taviani/kde-auth/internal/usecase"
)

func TestGetLogoutReturnsToTheRegisteredRedirect(t *testing.T) {
	sessions := &logoutSessions{}
	handler := NewLogout(usecase.NewLogout(sessions, logoutClock{}), logoutClients{
		client: domain.OAuthClient{
			ClientID:       "instacrane",
			RedirectURIs:   []string{"https://app.example/redirect", "instacrane://redirect"},
			AndroidPackage: "app.instacrane",
		},
	}, false)

	req := httptest.NewRequest(http.MethodGet, "/logout?client_id=instacrane&redirect_uri=https://app.example/redirect", nil)
	req.AddCookie(&http.Cookie{Name: response.SessionCookieName, Value: "raw-session"})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "https://app.example/redirect" {
		t.Fatalf("location %q", loc)
	}
	if cleared := rec.Result().Cookies(); len(cleared) != 1 || cleared[0].Name != response.SessionCookieName || cleared[0].MaxAge >= 0 {
		t.Fatalf("cookie %#v", cleared)
	}
	if len(sessions.revoked) != 1 || sessions.revoked[0] == "" {
		t.Fatalf("revoked %#v", sessions.revoked)
	}
}

func TestGetLogoutDropsAnUnknownRedirect(t *testing.T) {
	handler := NewLogout(usecase.NewLogout(&logoutSessions{}, logoutClock{}), logoutClients{
		client: domain.OAuthClient{ClientID: "instacrane", RedirectURIs: []string{"https://app.example/redirect"}},
	}, false)
	req := httptest.NewRequest(http.MethodGet, "/logout?client_id=instacrane&redirect_uri=https://elsewhere.example/steal", nil)
	req.AddCookie(&http.Cookie{Name: response.SessionCookieName, Value: "raw-session"})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "" {
		t.Fatalf("location %q", loc)
	}
}

func TestAndroidLogoutUsesTheIntentReturn(t *testing.T) {
	handler := NewLogout(usecase.NewLogout(&logoutSessions{}, logoutClock{}), logoutClients{
		client: domain.OAuthClient{
			ClientID:       "instacrane",
			RedirectURIs:   []string{"instacrane://redirect"},
			AndroidPackage: "app.instacrane",
		},
	}, false)
	req := httptest.NewRequest(http.MethodGet, "/logout?client_id=instacrane&redirect_uri=instacrane://redirect", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/120.0.0.0 Mobile")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("status %d", rec.Code)
	}
	const want = "intent://redirect#Intent;scheme=instacrane;package=app.instacrane;end"
	if loc := rec.Header().Get("Location"); loc != want {
		t.Fatalf("location %q", loc)
	}
}

type logoutClock struct{}

func (logoutClock) Now() time.Time { return time.Unix(1_700_000_000, 0).UTC() }

type logoutSessions struct {
	revoked []string
}

func (s *logoutSessions) Create(context.Context, domain.Session, string) error { return nil }
func (s *logoutSessions) ByTokenHash(context.Context, string, time.Time) (domain.Session, error) {
	return domain.Session{}, domain.ErrNotFound
}
func (s *logoutSessions) Revoke(_ context.Context, hash string, _ time.Time) error {
	s.revoked = append(s.revoked, hash)
	return nil
}
func (s *logoutSessions) RevokeAllForUser(context.Context, domain.UserID, time.Time) error {
	return nil
}

type logoutClients struct {
	client domain.OAuthClient
}

func (f logoutClients) ByClientID(context.Context, domain.ClientID) (domain.OAuthClient, error) {
	return f.client, nil
}
func (logoutClients) List(context.Context) ([]domain.OAuthClient, error) { return nil, nil }
func (logoutClients) Upsert(context.Context, domain.OAuthClient) error   { return nil }
func (logoutClients) UpdateAccessMode(context.Context, domain.ClientID, domain.AccessMode) error {
	return nil
}
func (logoutClients) UpdateRedirectURIs(context.Context, domain.ClientID, []string, string) error {
	return nil
}
