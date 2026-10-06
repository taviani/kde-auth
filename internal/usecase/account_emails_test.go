package usecase

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/taviani/kde-auth/internal/adapter/crypto"
	"github.com/taviani/kde-auth/internal/domain"
	"github.com/taviani/kde-auth/internal/port"
)

type memUserEmails struct {
	byUser map[domain.UserID][]domain.UserEmail
	all    map[domain.Email]domain.UserID
	nextID int
}

func (m *memUserEmails) ListByUser(_ context.Context, userID domain.UserID) ([]domain.UserEmail, error) {
	rows := m.byUser[userID]
	out := make([]domain.UserEmail, len(rows))
	copy(out, rows)
	return out, nil
}

func (m *memUserEmails) ByEmail(_ context.Context, email domain.Email) (domain.UserEmail, error) {
	for _, rows := range m.byUser {
		for _, row := range rows {
			if row.Email == email {
				return row, nil
			}
		}
	}
	return domain.UserEmail{}, domain.ErrNotFound
}

func (m *memUserEmails) HasSecondary(_ context.Context, userID domain.UserID) (bool, error) {
	for _, row := range m.byUser[userID] {
		if row.Role == domain.EmailRoleSecondary {
			return true, nil
		}
	}
	return false, nil
}

func (m *memUserEmails) CountVerified(_ context.Context, userID domain.UserID) (int, error) {
	n := 0
	for _, row := range m.byUser[userID] {
		if row.IsVerified() {
			n++
		}
	}
	return n, nil
}

func (m *memUserEmails) InsertPendingSecondary(_ context.Context, userID domain.UserID, email domain.Email, at time.Time) (domain.UserEmail, error) {
	m.nextID++
	ue := domain.UserEmail{
		ID:        domain.UserEmailID(fmt.Sprintf("ue-%d", m.nextID)),
		UserID:    userID,
		Email:     email,
		Role:      domain.EmailRoleSecondary,
		CreatedAt: at,
		UpdatedAt: at,
	}
	if m.byUser == nil {
		m.byUser = map[domain.UserID][]domain.UserEmail{}
	}
	if m.all == nil {
		m.all = map[domain.Email]domain.UserID{}
	}
	m.byUser[userID] = append(m.byUser[userID], ue)
	m.all[email] = userID
	return ue, nil
}

func (m *memUserEmails) MarkVerified(_ context.Context, userID domain.UserID, email domain.Email, at time.Time) error {
	rows := m.byUser[userID]
	for i := range rows {
		if rows[i].Email == email && rows[i].VerifiedAt == nil {
			rows[i].VerifiedAt = &at
			rows[i].UpdatedAt = at
			m.byUser[userID] = rows
			return nil
		}
	}
	return domain.ErrNotFound
}

func (m *memUserEmails) DeletePendingSecondary(_ context.Context, userID domain.UserID) error {
	rows := m.byUser[userID]
	kept := rows[:0]
	found := false
	for _, row := range rows {
		if row.Role == domain.EmailRoleSecondary && row.IsPending() {
			found = true
			delete(m.all, row.Email)
			continue
		}
		kept = append(kept, row)
	}
	if !found {
		return domain.ErrNotFound
	}
	m.byUser[userID] = kept
	return nil
}

func (m *memUserEmails) DeleteVerified(_ context.Context, userID domain.UserID, email domain.Email, at time.Time) error {
	rows := m.byUser[userID]
	var target *domain.UserEmail
	verified := 0
	for i := range rows {
		if rows[i].IsVerified() {
			verified++
		}
		if rows[i].Email == email {
			target = &rows[i]
		}
	}
	if target == nil {
		return domain.ErrNotFound
	}
	if !target.IsVerified() {
		return domain.ValidationError{Field: "email", Message: "email is not verified"}
	}
	if verified < 2 {
		return domain.ErrCannotDeleteLastEmail
	}
	wasPrimary := target.Role == domain.EmailRolePrimary
	kept := make([]domain.UserEmail, 0, len(rows)-1)
	for _, row := range rows {
		if row.Email == email {
			continue
		}
		kept = append(kept, row)
	}
	delete(m.all, email)
	if wasPrimary {
		for i := range kept {
			if kept[i].IsVerified() {
				kept[i].Role = domain.EmailRolePrimary
				kept[i].UpdatedAt = at
				break
			}
		}
	}
	m.byUser[userID] = kept
	return nil
}

type trackingMailer struct {
	lastTo  domain.Email
	lastURL string
}

func (m *trackingMailer) SendVerification(_ context.Context, to domain.Email, verifyURL string) error {
	m.lastTo = to
	m.lastURL = verifyURL
	return nil
}
func (m *trackingMailer) SendPasswordReset(context.Context, domain.Email, string) error { return nil }
func (m *trackingMailer) SendInvite(context.Context, domain.Email, string, string) error {
	return nil
}

type trackingVerifyTokens struct {
	created []domain.EmailVerificationToken
	byHash  map[string]domain.EmailVerificationToken
}

func (m *trackingVerifyTokens) CreateAuthorizationCode(context.Context, domain.AuthorizationCode, string) error {
	return nil
}
func (m *trackingVerifyTokens) ConsumeAuthorizationCode(context.Context, string, time.Time) (domain.AuthorizationCode, error) {
	return domain.AuthorizationCode{}, domain.ErrNotFound
}
func (m *trackingVerifyTokens) CreateRefreshToken(context.Context, domain.RefreshToken, string) error {
	return nil
}
func (m *trackingVerifyTokens) ConsumeRefreshToken(context.Context, string, time.Time) (domain.RefreshToken, error) {
	return domain.RefreshToken{}, domain.ErrNotFound
}
func (m *trackingVerifyTokens) RevokeRefreshToken(context.Context, string, time.Time) error {
	return nil
}
func (m *trackingVerifyTokens) RevokeAllRefreshTokensForUser(context.Context, domain.UserID, time.Time) error {
	return nil
}
func (m *trackingVerifyTokens) CreateEmailVerificationToken(_ context.Context, token domain.EmailVerificationToken, tokenHash string) error {
	m.created = append(m.created, token)
	if m.byHash == nil {
		m.byHash = map[string]domain.EmailVerificationToken{}
	}
	m.byHash[tokenHash] = token
	return nil
}
func (m *trackingVerifyTokens) ConsumeEmailVerificationToken(_ context.Context, tokenHash string, at time.Time) (domain.EmailVerificationToken, error) {
	t, ok := m.byHash[tokenHash]
	if !ok {
		return domain.EmailVerificationToken{}, domain.ErrNotFound
	}
	if !at.Before(t.ExpiresAt) {
		return domain.EmailVerificationToken{}, domain.ErrInvalidToken
	}
	delete(m.byHash, tokenHash)
	return t, nil
}
func (m *trackingVerifyTokens) CreatePasswordResetToken(context.Context, domain.PasswordResetToken, string) error {
	return nil
}
func (m *trackingVerifyTokens) ConsumePasswordResetToken(context.Context, string, time.Time) (domain.PasswordResetToken, error) {
	return domain.PasswordResetToken{}, domain.ErrNotFound
}

type accountUsers struct {
	byID   map[domain.UserID]domain.User
	emails *memUserEmails
}

func (m *accountUsers) Create(context.Context, domain.User) (domain.UserID, error) {
	return "", domain.ErrNotFound
}
func (m *accountUsers) ByEmail(_ context.Context, email domain.Email) (domain.User, error) {
	for _, rows := range m.emails.byUser {
		for _, row := range rows {
			if row.Email == email && row.IsVerified() {
				u, ok := m.byID[row.UserID]
				if !ok {
					return domain.User{}, domain.ErrNotFound
				}
				return u, nil
			}
		}
	}
	return domain.User{}, domain.ErrNotFound
}
func (m *accountUsers) ByID(_ context.Context, id domain.UserID) (domain.User, error) {
	u, ok := m.byID[id]
	if !ok {
		return domain.User{}, domain.ErrNotFound
	}
	return u, nil
}
func (m *accountUsers) MarkEmailVerified(_ context.Context, id domain.UserID, at time.Time) error {
	u, ok := m.byID[id]
	if !ok {
		return domain.ErrNotFound
	}
	u.EmailVerifiedAt = &at
	u.Status = domain.UserStatusActive
	u.UpdatedAt = at
	m.byID[id] = u
	_ = m.emails.MarkVerified(context.Background(), id, u.Email, at)
	return nil
}
func (m *accountUsers) UpdatePassword(context.Context, domain.UserID, domain.PasswordHash, time.Time) error {
	return nil
}
func (m *accountUsers) ExistsByEmail(_ context.Context, email domain.Email) (bool, error) {
	if m.emails.all != nil {
		_, ok := m.emails.all[email]
		return ok, nil
	}
	return false, nil
}

func seedAccountUser(now time.Time) (*accountUsers, *memUserEmails, domain.UserID) {
	id := domain.UserID("user-1")
	primary := domain.Email("primary@example.com")
	user := domain.User{
		ID:              id,
		Email:           primary,
		PasswordHash:    "h:secret",
		Role:            domain.RoleUser,
		Status:          domain.UserStatusActive,
		EmailVerifiedAt: &now,
		CreatedAt:       now,
		UpdatedAt:       now,
	}
	emails := &memUserEmails{
		byUser: map[domain.UserID][]domain.UserEmail{
			id: {{
				ID:         "ue-1",
				UserID:     id,
				Email:      primary,
				Role:       domain.EmailRolePrimary,
				VerifiedAt: &now,
				CreatedAt:  now,
				UpdatedAt:  now,
			}},
		},
		all: map[domain.Email]domain.UserID{primary: id},
	}
	users := &accountUsers{
		byID:   map[domain.UserID]domain.User{id: user},
		emails: emails,
	}
	return users, emails, id
}

func TestAccountEmailsAddVerifyCancelDelete(t *testing.T) {
	now := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	users, emails, userID := seedAccountUser(now)
	tokens := &trackingVerifyTokens{}
	mailer := &trackingMailer{}
	uc := NewAccountEmails(users, emails, tokens, mailer, port.NoopCaptcha{}, frozenClock{t: now}, stubIssuer{url: "https://auth.example"})
	verify := NewVerifyEmail(users, emails, tokens, frozenClock{t: now})

	if err := uc.Add(context.Background(), AddEmailInput{
		UserID: userID,
		Email:  "secondary@example.com",
	}); err != nil {
		t.Fatal(err)
	}
	if mailer.lastTo != "secondary@example.com" {
		t.Fatalf("mail to: %s", mailer.lastTo)
	}
	if len(tokens.created) != 1 || tokens.created[0].Email != "secondary@example.com" {
		t.Fatalf("token: %+v", tokens.created)
	}
	if err := uc.Add(context.Background(), AddEmailInput{UserID: userID, Email: "other@example.com"}); !errors.Is(err, domain.ErrEmailLimitReached) {
		t.Fatalf("second add: %v", err)
	}

	list, err := uc.List(context.Background(), userID)
	if err != nil || len(list) != 2 || !list[1].Pending {
		t.Fatalf("list pending: %+v %v", list, err)
	}

	raw := tokens.created[0].Token
	if err := verify.Execute(context.Background(), raw); err != nil {
		t.Fatal(err)
	}

	list, err = uc.List(context.Background(), userID)
	if err != nil || len(list) != 2 || !list[1].Verified {
		t.Fatalf("list verified: %+v %v", list, err)
	}

	if _, err := users.ByEmail(context.Background(), "secondary@example.com"); err != nil {
		t.Fatalf("login by secondary: %v", err)
	}

	if err := uc.Delete(context.Background(), DeleteEmailInput{UserID: userID, Email: "primary@example.com"}); err != nil {
		t.Fatal(err)
	}
	list, err = uc.List(context.Background(), userID)
	if err != nil || len(list) != 1 || list[0].Email != "secondary@example.com" || list[0].Role != "primary" {
		t.Fatalf("after promote: %+v %v", list, err)
	}
	if err := uc.Delete(context.Background(), DeleteEmailInput{UserID: userID, Email: "secondary@example.com"}); !errors.Is(err, domain.ErrCannotDeleteLastEmail) {
		t.Fatalf("last delete: %v", err)
	}
}

func TestAccountEmailsCancelPending(t *testing.T) {
	now := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	users, emails, userID := seedAccountUser(now)
	tokens := &trackingVerifyTokens{}
	uc := NewAccountEmails(users, emails, tokens, &trackingMailer{}, port.NoopCaptcha{}, frozenClock{t: now}, stubIssuer{url: "https://auth.example"})

	if err := uc.Add(context.Background(), AddEmailInput{UserID: userID, Email: "pending@example.com"}); err != nil {
		t.Fatal(err)
	}
	if err := uc.Cancel(context.Background(), userID); err != nil {
		t.Fatal(err)
	}
	list, err := uc.List(context.Background(), userID)
	if err != nil || len(list) != 1 {
		t.Fatalf("after cancel: %+v %v", list, err)
	}
	if err := uc.Add(context.Background(), AddEmailInput{UserID: userID, Email: "new@example.com"}); err != nil {
		t.Fatal(err)
	}
}

func TestAccountEmailsRejectsTakenAndSelf(t *testing.T) {
	now := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	users, emails, userID := seedAccountUser(now)
	emails.all["taken@example.com"] = "other"
	uc := NewAccountEmails(users, emails, &trackingVerifyTokens{}, &trackingMailer{}, port.NoopCaptcha{}, frozenClock{t: now}, stubIssuer{url: "https://auth.example"})

	if err := uc.Add(context.Background(), AddEmailInput{UserID: userID, Email: "primary@example.com"}); !errors.Is(err, domain.ErrEmailTaken) {
		t.Fatalf("self: %v", err)
	}
	if err := uc.Add(context.Background(), AddEmailInput{UserID: userID, Email: "taken@example.com"}); !errors.Is(err, domain.ErrEmailTaken) {
		t.Fatalf("taken: %v", err)
	}
}

func TestVerifyEmailPrimarySignup(t *testing.T) {
	now := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	id := domain.UserID("pending-user")
	primary := domain.Email("new@example.com")
	emails := &memUserEmails{
		byUser: map[domain.UserID][]domain.UserEmail{
			id: {{
				ID:     "ue-1",
				UserID: id,
				Email:  primary,
				Role:   domain.EmailRolePrimary,
			}},
		},
		all: map[domain.Email]domain.UserID{primary: id},
	}
	users := &accountUsers{
		byID: map[domain.UserID]domain.User{
			id: {
				ID:     id,
				Email:  primary,
				Status: domain.UserStatusPending,
			},
		},
		emails: emails,
	}
	tokens := &trackingVerifyTokens{}
	raw := "raw-verify-token"
	_ = tokens.CreateEmailVerificationToken(context.Background(), domain.EmailVerificationToken{
		Token:     raw,
		UserID:    id,
		ExpiresAt: now.Add(time.Hour),
	}, crypto.HashToken(raw))

	verify := NewVerifyEmail(users, emails, tokens, frozenClock{t: now})
	if err := verify.Execute(context.Background(), raw); err != nil {
		t.Fatal(err)
	}
	u, err := users.ByID(context.Background(), id)
	if err != nil || u.Status != domain.UserStatusActive || u.EmailVerifiedAt == nil {
		t.Fatalf("user: %+v %v", u, err)
	}
	row, err := emails.ByEmail(context.Background(), primary)
	if err != nil || !row.IsVerified() {
		t.Fatalf("primary email: %+v %v", row, err)
	}
}
