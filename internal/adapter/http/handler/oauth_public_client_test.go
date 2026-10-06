package handler

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/taviani/kde-auth/internal/adapter/crypto"
	"github.com/taviani/kde-auth/internal/adapter/http/render"
	"github.com/taviani/kde-auth/internal/adapter/http/response"
	"github.com/taviani/kde-auth/internal/domain"
	"github.com/taviani/kde-auth/internal/port"
	"github.com/taviani/kde-auth/internal/usecase"
)

// RFC 7636 appendix B.
const (
	testVerifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	testChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	testHTTPS     = "https://app.example/redirect"
	testScheme    = "app.example://redirect"
)

func TestPublicClientHTTPSRedirectExchangesOnce(t *testing.T) {
	client, base := newPublicClientServer(t)

	code := authorizeCode(t, client, base, testHTTPS)
	body := exchangeCode(t, client, base, code, testVerifier, testHTTPS)
	if body["access_token"] == "" || body["refresh_token"] == "" {
		t.Fatalf("expected tokens, got %#v", body)
	}

	again := postToken(t, client, base, code, testVerifier, testHTTPS)
	if again.StatusCode != http.StatusBadRequest {
		t.Fatalf("replay status %d", again.StatusCode)
	}
	var replay map[string]string
	decodeJSON(t, again, &replay)
	if replay["error"] != "invalid_grant" {
		t.Fatalf("replay error %q", replay["error"])
	}
}

func TestPublicClientWrongVerifierIsRejected(t *testing.T) {
	client, base := newPublicClientServer(t)
	code := authorizeCode(t, client, base, testHTTPS)
	res := postToken(t, client, base, code, testVerifier[:len(testVerifier)-1]+"0", testHTTPS)
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("status %d", res.StatusCode)
	}
	var body map[string]string
	decodeJSON(t, res, &body)
	if body["error"] != "invalid_grant" {
		t.Fatalf("error %q", body["error"])
	}
}

func TestCustomSchemeAuthorizeDoesNotRedirect(t *testing.T) {
	client, base := newPublicClientServer(t)
	res := authorize(t, client, base, testScheme)
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status %d, want 200", res.StatusCode)
	}
	raw, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	page := string(raw)
	if !strings.Contains(page, "Open the app to continue") {
		t.Fatalf("expected the app-open page, got %s", page)
	}
	if !strings.Contains(page, "code=") {
		t.Fatal("expected the code in the app link")
	}
}

func newPublicClientServer(t *testing.T) (*http.Client, string) {
	t.Helper()
	now := time.Date(2026, 10, 6, 8, 0, 0, 0, time.UTC)
	verified := now
	user := domain.User{
		ID:              "user-1",
		Email:           "ada@example.com",
		Role:            domain.RoleUser,
		Status:          domain.UserStatusActive,
		EmailVerifiedAt: &verified,
	}
	clients := &memClients{byID: map[domain.ClientID]domain.OAuthClient{
		"app": {
			ClientID:                "app",
			Name:                    "App",
			RedirectURIs:            []string{testHTTPS, testScheme},
			AccessMode:              domain.AccessModePublic,
			TokenEndpointAuthMethod: domain.TokenAuthNone,
		},
	}}
	sessions := &memSessions{byHash: map[string]domain.Session{
		crypto.HashToken("raw-session"): {
			UserID:    user.ID,
			ExpiresAt: now.Add(time.Hour),
		},
	}}
	users := &memUsers{byID: map[domain.UserID]domain.User{user.ID: user}}
	tokens := &memTokens{codes: map[string]domain.AuthorizationCode{}}
	clock := fixedClock{now}
	renderer, err := render.New()
	if err != nil {
		t.Fatal(err)
	}
	authorizeUC := usecase.NewAuthorize(clients, tokens, usecase.NewResolveSession(sessions, users, clock), nil, clock)
	tokenUC := usecase.NewExchangeToken(clients, tokens, users, stubHasher{}, fixedIssuer{}, clock)
	mux := http.NewServeMux()
	mux.Handle("/authorize", NewAuthorize(authorizeUC, nil, renderer, false))
	mux.Handle("/token", NewToken(tokenUC))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	httpClient := srv.Client()
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return httpClient, srv.URL
}

func authorizeCode(t *testing.T, client *http.Client, base, redirectURI string) string {
	t.Helper()
	res := authorize(t, client, base, redirectURI)
	defer res.Body.Close()
	if res.StatusCode != http.StatusFound {
		t.Fatalf("status %d, want 302", res.StatusCode)
	}
	loc, err := res.Location()
	if err != nil {
		t.Fatal(err)
	}
	if loc.Scheme != "https" || loc.Host != "app.example" || loc.Path != "/redirect" {
		t.Fatalf("location %s", loc)
	}
	if loc.Query().Get("state") != "state-1" {
		t.Fatalf("state %q", loc.Query().Get("state"))
	}
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatal("missing code")
	}
	return code
}

func authorize(t *testing.T, client *http.Client, base, redirectURI string) *http.Response {
	t.Helper()
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {"app"},
		"redirect_uri":          {redirectURI},
		"scope":                 {"openid email offline_access"},
		"state":                 {"state-1"},
		"code_challenge":        {testChallenge},
		"code_challenge_method": {"S256"},
	}
	req, err := http.NewRequest(http.MethodGet, base+"/authorize?"+q.Encode(), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(&http.Cookie{Name: response.SessionCookieName, Value: "raw-session"})
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func exchangeCode(t *testing.T, client *http.Client, base, code, verifier, redirectURI string) map[string]any {
	t.Helper()
	res := postToken(t, client, base, code, verifier, redirectURI)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status %d", res.StatusCode)
	}
	var body map[string]any
	decodeJSON(t, res, &body)
	return body
}

func postToken(t *testing.T, client *http.Client, base, code, verifier, redirectURI string) *http.Response {
	t.Helper()
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"client_id":     {"app"},
		"code_verifier": {verifier},
	}
	res, err := client.PostForm(base+"/token", form)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func decodeJSON(t *testing.T, res *http.Response, dest any) {
	t.Helper()
	defer res.Body.Close()
	if err := json.NewDecoder(res.Body).Decode(dest); err != nil {
		t.Fatal(err)
	}
}

type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

type fixedIssuer struct{}

func (fixedIssuer) Issuer() string { return "https://issuer.example" }
func (fixedIssuer) AccessToken(context.Context, port.AccessClaims) (string, error) {
	return "access-token", nil
}
func (fixedIssuer) ParseAccessToken(context.Context, string) (port.AccessClaims, error) {
	return port.AccessClaims{}, domain.ErrUnauthorized
}
func (fixedIssuer) JWKS(context.Context) (map[string]any, error) {
	return map[string]any{}, nil
}

type stubHasher struct{}

func (stubHasher) Hash(context.Context, domain.PlainPassword) (domain.PasswordHash, error) {
	return "", nil
}
func (stubHasher) Verify(domain.PasswordHash, domain.PlainPassword) bool { return false }

type memClients struct {
	byID map[domain.ClientID]domain.OAuthClient
}

func (m *memClients) ByClientID(_ context.Context, id domain.ClientID) (domain.OAuthClient, error) {
	c, ok := m.byID[id]
	if !ok {
		return domain.OAuthClient{}, domain.ErrNotFound
	}
	return c, nil
}
func (m *memClients) List(context.Context) ([]domain.OAuthClient, error) { return nil, nil }
func (m *memClients) Upsert(context.Context, domain.OAuthClient) error   { return nil }
func (m *memClients) UpdateAccessMode(context.Context, domain.ClientID, domain.AccessMode) error {
	return nil
}

type memSessions struct {
	byHash map[string]domain.Session
}

func (m *memSessions) Create(context.Context, domain.Session, string) error { return nil }
func (m *memSessions) ByTokenHash(_ context.Context, hash string, at time.Time) (domain.Session, error) {
	s, ok := m.byHash[hash]
	if !ok || !at.Before(s.ExpiresAt) {
		return domain.Session{}, domain.ErrNotFound
	}
	return s, nil
}
func (m *memSessions) Revoke(context.Context, string, time.Time) error { return nil }
func (m *memSessions) RevokeAllForUser(context.Context, domain.UserID, time.Time) error {
	return nil
}

type memUsers struct {
	byID map[domain.UserID]domain.User
}

func (m *memUsers) Create(context.Context, domain.User) (domain.UserID, error) {
	return "", nil
}
func (m *memUsers) ByEmail(context.Context, domain.Email) (domain.User, error) {
	return domain.User{}, domain.ErrNotFound
}
func (m *memUsers) ByID(_ context.Context, id domain.UserID) (domain.User, error) {
	u, ok := m.byID[id]
	if !ok {
		return domain.User{}, domain.ErrNotFound
	}
	return u, nil
}
func (m *memUsers) MarkEmailVerified(context.Context, domain.UserID, time.Time) error { return nil }
func (m *memUsers) UpdatePassword(context.Context, domain.UserID, domain.PasswordHash, time.Time) error {
	return nil
}
func (m *memUsers) ExistsByEmail(context.Context, domain.Email) (bool, error) { return false, nil }

type memTokens struct {
	codes map[string]domain.AuthorizationCode
}

func (m *memTokens) CreateAuthorizationCode(_ context.Context, code domain.AuthorizationCode, codeHash string) error {
	m.codes[codeHash] = code
	return nil
}
func (m *memTokens) ConsumeAuthorizationCode(_ context.Context, codeHash string, at time.Time) (domain.AuthorizationCode, error) {
	code, ok := m.codes[codeHash]
	if !ok || !at.Before(code.ExpiresAt) {
		return domain.AuthorizationCode{}, domain.ErrNotFound
	}
	delete(m.codes, codeHash)
	return code, nil
}
func (m *memTokens) CreateRefreshToken(context.Context, domain.RefreshToken, string) error {
	return nil
}
func (m *memTokens) ConsumeRefreshToken(context.Context, string, time.Time) (domain.RefreshToken, error) {
	return domain.RefreshToken{}, domain.ErrNotFound
}
func (m *memTokens) RevokeRefreshToken(context.Context, string, time.Time) error { return nil }
func (m *memTokens) RevokeAllRefreshTokensForUser(context.Context, domain.UserID, time.Time) error {
	return nil
}
func (m *memTokens) CreateEmailVerificationToken(context.Context, domain.EmailVerificationToken, string) error {
	return nil
}
func (m *memTokens) ConsumeEmailVerificationToken(context.Context, string, time.Time) (domain.EmailVerificationToken, error) {
	return domain.EmailVerificationToken{}, domain.ErrNotFound
}
func (m *memTokens) CreatePasswordResetToken(context.Context, domain.PasswordResetToken, string) error {
	return nil
}
func (m *memTokens) ConsumePasswordResetToken(context.Context, string, time.Time) (domain.PasswordResetToken, error) {
	return domain.PasswordResetToken{}, domain.ErrNotFound
}
