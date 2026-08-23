package usecase

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/taviani/kde-auth/internal/domain"
	"github.com/taviani/kde-auth/internal/port"
)

type frozenClock struct{ t time.Time }

func (c frozenClock) Now() time.Time { return c.t }

type stubHasher struct{}

func (stubHasher) Hash(_ context.Context, p domain.PlainPassword) (domain.PasswordHash, error) {
	return domain.PasswordHash("h:" + string(p)), nil
}

func (stubHasher) Verify(hash domain.PasswordHash, p domain.PlainPassword) bool {
	return hash == domain.PasswordHash("h:"+string(p))
}

type stubIssuer struct{ url string }

func (s stubIssuer) Issuer() string { return s.url }
func (stubIssuer) AccessToken(context.Context, port.AccessClaims) (string, error) {
	return "", nil
}
func (stubIssuer) ParseAccessToken(context.Context, string) (port.AccessClaims, error) {
	return port.AccessClaims{}, nil
}
func (stubIssuer) JWKS(context.Context) (map[string]any, error) { return nil, nil }

type memClients struct{ byID map[domain.ClientID]domain.OAuthClient }

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

type memTickets struct {
	byHash map[string]domain.RegistrationTicket
}

func (m *memTickets) Create(_ context.Context, ticket domain.RegistrationTicket, tokenHash string) error {
	if m.byHash == nil {
		m.byHash = map[string]domain.RegistrationTicket{}
	}
	m.byHash[tokenHash] = ticket
	return nil
}

func (m *memTickets) Peek(_ context.Context, tokenHash string, at time.Time) (domain.RegistrationTicket, error) {
	t, ok := m.byHash[tokenHash]
	if !ok {
		return domain.RegistrationTicket{}, domain.ErrNotFound
	}
	if t.UsedAt != nil || !at.Before(t.ExpiresAt) {
		return domain.RegistrationTicket{}, domain.ErrInvalidToken
	}
	return t, nil
}

func (m *memTickets) Consume(_ context.Context, tokenHash string, at time.Time) (domain.RegistrationTicket, error) {
	t, err := m.Peek(context.Background(), tokenHash, at)
	if err != nil {
		return domain.RegistrationTicket{}, err
	}
	used := at
	t.UsedAt = &used
	m.byHash[tokenHash] = t
	return t, nil
}

func publicAccessClient() domain.OAuthClient {
	return domain.OAuthClient{
		ClientID:                "web-app",
		ClientSecretHash:        "h:super-secret-16",
		Name:                    "Web",
		RedirectURIs:            []string{"https://app.example/callback"},
		AccessMode:              domain.AccessModePublic,
		TokenEndpointAuthMethod: domain.TokenAuthClientSecretPost,
	}
}

func TestIssueRegisterTicketRejectsPublicAndInviteOnlyClients(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	clients := &memClients{byID: map[domain.ClientID]domain.OAuthClient{
		"web-app": publicAccessClient(),
		"mobile": {
			ClientID:                "mobile",
			Name:                    "Mobile",
			RedirectURIs:            []string{"app://cb"},
			AccessMode:              domain.AccessModePublic,
			TokenEndpointAuthMethod: domain.TokenAuthNone,
		},
		"private": {
			ClientID:                "private",
			ClientSecretHash:        "h:super-secret-16",
			Name:                    "Private",
			RedirectURIs:            []string{"https://app.example/callback"},
			AccessMode:              domain.AccessModeInviteOnly,
			TokenEndpointAuthMethod: domain.TokenAuthClientSecretPost,
		},
	}}
	tickets := &memTickets{}
	uc := NewIssueRegisterTicket(clients, tickets, stubHasher{}, stubIssuer{url: "https://auth.example"}, frozenClock{t: now}, true)

	if _, err := uc.Execute(context.Background(), IssueRegisterTicketInput{ClientID: "mobile", ClientSecret: ""}); !errors.Is(err, domain.ErrInvalidClient) {
		t.Fatalf("public client: %v", err)
	}
	if _, err := uc.Execute(context.Background(), IssueRegisterTicketInput{ClientID: "private", ClientSecret: "super-secret-16"}); !errors.Is(err, domain.ErrInviteOnlyRegistration) {
		t.Fatalf("invite-only: %v", err)
	}
	if _, err := uc.Execute(context.Background(), IssueRegisterTicketInput{ClientID: "web-app", ClientSecret: "wrong"}); !errors.Is(err, domain.ErrInvalidClient) {
		t.Fatalf("bad secret: %v", err)
	}
	got, err := uc.Execute(context.Background(), IssueRegisterTicketInput{ClientID: "web-app", ClientSecret: "super-secret-16"})
	if err != nil {
		t.Fatal(err)
	}
	if got.Ticket == "" || got.ExpiresIn != 600 {
		t.Fatalf("ticket result: %+v", got)
	}
}

type memUsers struct {
	byEmail map[domain.Email]domain.User
	nextID  int
}

func (m *memUsers) Create(_ context.Context, user domain.User) (domain.UserID, error) {
	m.nextID++
	id := domain.UserID("user-1")
	user.ID = id
	if m.byEmail == nil {
		m.byEmail = map[domain.Email]domain.User{}
	}
	m.byEmail[user.Email] = user
	return id, nil
}
func (m *memUsers) ByEmail(_ context.Context, email domain.Email) (domain.User, error) {
	u, ok := m.byEmail[email]
	if !ok {
		return domain.User{}, domain.ErrNotFound
	}
	return u, nil
}
func (m *memUsers) ByID(context.Context, domain.UserID) (domain.User, error) {
	return domain.User{}, domain.ErrNotFound
}
func (m *memUsers) MarkEmailVerified(context.Context, domain.UserID, time.Time) error { return nil }
func (m *memUsers) UpdatePassword(context.Context, domain.UserID, domain.PasswordHash, time.Time) error {
	return nil
}
func (m *memUsers) ExistsByEmail(_ context.Context, email domain.Email) (bool, error) {
	_, ok := m.byEmail[email]
	return ok, nil
}

type memAccesses struct {
	granted []domain.UserAppAccess
}

func (m *memAccesses) Upsert(_ context.Context, access domain.UserAppAccess) error {
	m.granted = append(m.granted, access)
	return nil
}
func (m *memAccesses) HasAccess(context.Context, domain.UserID, domain.ClientID) (bool, error) {
	return false, nil
}

type memTokens struct{}

func (memTokens) CreateAuthorizationCode(context.Context, domain.AuthorizationCode, string) error {
	return nil
}
func (memTokens) ConsumeAuthorizationCode(context.Context, string, time.Time) (domain.AuthorizationCode, error) {
	return domain.AuthorizationCode{}, domain.ErrNotFound
}
func (memTokens) CreateRefreshToken(context.Context, domain.RefreshToken, string) error { return nil }
func (memTokens) ConsumeRefreshToken(context.Context, string, time.Time) (domain.RefreshToken, error) {
	return domain.RefreshToken{}, domain.ErrNotFound
}
func (memTokens) RevokeRefreshToken(context.Context, string, time.Time) error { return nil }
func (memTokens) RevokeAllRefreshTokensForUser(context.Context, domain.UserID, time.Time) error {
	return nil
}
func (memTokens) CreateEmailVerificationToken(context.Context, domain.EmailVerificationToken, string) error {
	return nil
}
func (memTokens) ConsumeEmailVerificationToken(context.Context, string, time.Time) (domain.EmailVerificationToken, error) {
	return domain.EmailVerificationToken{}, domain.ErrNotFound
}
func (memTokens) CreatePasswordResetToken(context.Context, domain.PasswordResetToken, string) error {
	return nil
}
func (memTokens) ConsumePasswordResetToken(context.Context, string, time.Time) (domain.PasswordResetToken, error) {
	return domain.PasswordResetToken{}, domain.ErrNotFound
}

type stubMailer struct{}

func (stubMailer) SendVerification(context.Context, domain.Email, string) error { return nil }
func (stubMailer) SendPasswordReset(context.Context, domain.Email, string) error {
	return nil
}
func (stubMailer) SendInvite(context.Context, domain.Email, string, string) error { return nil }

func TestRegisterUserRequiresTicket(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	tickets := &memTickets{byHash: map[string]domain.RegistrationTicket{}}
	users := &memUsers{}
	accesses := &memAccesses{}
	uc := NewRegisterUser(users, tickets, accesses, stubHasher{}, memTokens{}, stubMailer{}, port.NoopCaptcha{}, frozenClock{t: now}, stubIssuer{url: "https://auth.example"}, true)

	err := uc.Execute(context.Background(), RegisterInput{
		Email:    "a@example.com",
		Password: "twelvechars!!",
		Ticket:   "",
	})
	if !errors.Is(err, domain.ErrInvalidToken) {
		t.Fatalf("empty ticket: %v", err)
	}

	issue := NewIssueRegisterTicket(&memClients{byID: map[domain.ClientID]domain.OAuthClient{"web-app": publicAccessClient()}}, tickets, stubHasher{}, stubIssuer{url: "https://auth.example"}, frozenClock{t: now}, true)
	issued, err := issue.Execute(context.Background(), IssueRegisterTicketInput{ClientID: "web-app", ClientSecret: "super-secret-16"})
	if err != nil {
		t.Fatal(err)
	}
	if err := uc.Execute(context.Background(), RegisterInput{
		Email:    "a@example.com",
		Password: "twelvechars!!",
		Ticket:   issued.Ticket,
	}); err != nil {
		t.Fatal(err)
	}
	if len(accesses.granted) != 1 || accesses.granted[0].ClientID != "web-app" {
		t.Fatalf("access: %+v", accesses.granted)
	}
	if err := uc.Execute(context.Background(), RegisterInput{
		Email:    "b@example.com",
		Password: "twelvechars!!",
		Ticket:   issued.Ticket,
	}); !errors.Is(err, domain.ErrInvalidToken) {
		t.Fatalf("replay ticket: %v", err)
	}
}

func TestAdminRevokeSessions(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	repo := &memAdminUsers{byID: map[domain.UserID]domain.User{
		"admin": {ID: "admin", Role: domain.RoleAdmin, Email: "admin@example.com"},
		"user":  {ID: "user", Role: domain.RoleUser, Email: "u@example.com"},
	}}
	sessions := &trackingSessions{}
	tokens := &trackingRefreshTokens{}
	uc := NewAdminUsers(repo, sessions, tokens, frozenClock{t: now})
	actor := repo.byID["admin"]

	if err := uc.RevokeSessions(context.Background(), actor, "user"); err != nil {
		t.Fatal(err)
	}
	if len(sessions.revoked) != 1 || sessions.revoked[0] != "user" {
		t.Fatalf("sessions revoked: %+v", sessions.revoked)
	}
	if len(tokens.revoked) != 1 || tokens.revoked[0] != "user" {
		t.Fatalf("refresh tokens revoked: %+v", tokens.revoked)
	}

	nonAdmin := repo.byID["user"]
	if err := uc.RevokeSessions(context.Background(), nonAdmin, "admin"); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("expected forbidden, got %v", err)
	}
}

func TestAdminDeleteRejectsSelfAndAdmins(t *testing.T) {
	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	repo := &memAdminUsers{byID: map[domain.UserID]domain.User{
		"admin": {ID: "admin", Role: domain.RoleAdmin, Email: "admin@example.com"},
		"other-admin": {ID: "other-admin", Role: domain.RoleAdmin, Email: "a2@example.com"},
		"user":  {ID: "user", Role: domain.RoleUser, Email: "u@example.com"},
	}}
	uc := NewAdminUsers(repo, memSessions{}, memTokens{}, frozenClock{t: now})
	actor := repo.byID["admin"]
	if err := uc.Delete(context.Background(), actor, "admin"); err == nil {
		t.Fatal("expected self-delete to fail")
	}
	if err := uc.Delete(context.Background(), actor, "other-admin"); err == nil {
		t.Fatal("expected admin delete to fail")
	}
	if err := uc.Delete(context.Background(), actor, "user"); err != nil {
		t.Fatal(err)
	}
	if _, ok := repo.byID["user"]; ok {
		t.Fatal("user should be deleted")
	}
}

type memAdminUsers struct {
	byID map[domain.UserID]domain.User
}

func (m *memAdminUsers) List(context.Context, domain.UserListFilter) ([]domain.User, error) {
	return nil, nil
}
func (m *memAdminUsers) Count(context.Context, domain.UserListFilter) (int, error) { return 0, nil }
func (m *memAdminUsers) Stats(context.Context, time.Time) (domain.UserStats, error) {
	return domain.UserStats{}, nil
}
func (m *memAdminUsers) ByID(_ context.Context, id domain.UserID) (domain.User, error) {
	u, ok := m.byID[id]
	if !ok {
		return domain.User{}, domain.ErrNotFound
	}
	return u, nil
}
func (m *memAdminUsers) SetStatus(context.Context, domain.UserID, domain.UserStatus, time.Time) error {
	return nil
}
func (m *memAdminUsers) Delete(_ context.Context, id domain.UserID) error {
	if _, ok := m.byID[id]; !ok {
		return domain.ErrNotFound
	}
	delete(m.byID, id)
	return nil
}
func (m *memAdminUsers) ListClientIDsForUsers(context.Context, []domain.UserID) (map[domain.UserID][]domain.ClientID, error) {
	return map[domain.UserID][]domain.ClientID{}, nil
}

type memSessions struct{}

func (memSessions) Create(context.Context, domain.Session, string) error { return nil }
func (memSessions) ByTokenHash(context.Context, string, time.Time) (domain.Session, error) {
	return domain.Session{}, domain.ErrNotFound
}
func (memSessions) Revoke(context.Context, string, time.Time) error { return nil }
func (memSessions) RevokeAllForUser(context.Context, domain.UserID, time.Time) error {
	return nil
}

type trackingSessions struct {
	revoked []domain.UserID
}

func (m *trackingSessions) Create(context.Context, domain.Session, string) error { return nil }
func (m *trackingSessions) ByTokenHash(context.Context, string, time.Time) (domain.Session, error) {
	return domain.Session{}, domain.ErrNotFound
}
func (m *trackingSessions) Revoke(context.Context, string, time.Time) error { return nil }
func (m *trackingSessions) RevokeAllForUser(_ context.Context, userID domain.UserID, _ time.Time) error {
	m.revoked = append(m.revoked, userID)
	return nil
}

type trackingRefreshTokens struct {
	revoked []domain.UserID
}

func (m *trackingRefreshTokens) CreateAuthorizationCode(context.Context, domain.AuthorizationCode, string) error {
	return nil
}
func (m *trackingRefreshTokens) ConsumeAuthorizationCode(context.Context, string, time.Time) (domain.AuthorizationCode, error) {
	return domain.AuthorizationCode{}, domain.ErrNotFound
}
func (m *trackingRefreshTokens) CreateRefreshToken(context.Context, domain.RefreshToken, string) error {
	return nil
}
func (m *trackingRefreshTokens) ConsumeRefreshToken(context.Context, string, time.Time) (domain.RefreshToken, error) {
	return domain.RefreshToken{}, domain.ErrNotFound
}
func (m *trackingRefreshTokens) RevokeRefreshToken(context.Context, string, time.Time) error { return nil }
func (m *trackingRefreshTokens) RevokeAllRefreshTokensForUser(_ context.Context, userID domain.UserID, _ time.Time) error {
	m.revoked = append(m.revoked, userID)
	return nil
}
func (m *trackingRefreshTokens) CreateEmailVerificationToken(context.Context, domain.EmailVerificationToken, string) error {
	return nil
}
func (m *trackingRefreshTokens) ConsumeEmailVerificationToken(context.Context, string, time.Time) (domain.EmailVerificationToken, error) {
	return domain.EmailVerificationToken{}, domain.ErrNotFound
}
func (m *trackingRefreshTokens) CreatePasswordResetToken(context.Context, domain.PasswordResetToken, string) error {
	return nil
}
func (m *trackingRefreshTokens) ConsumePasswordResetToken(context.Context, string, time.Time) (domain.PasswordResetToken, error) {
	return domain.PasswordResetToken{}, domain.ErrNotFound
}
