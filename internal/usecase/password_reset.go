package usecase

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/taviani/kde-auth/internal/adapter/crypto"
	"github.com/taviani/kde-auth/internal/domain"
	"github.com/taviani/kde-auth/internal/port"
)

const passwordResetTTL = time.Hour

type RequestPasswordReset struct {
	users   port.UserRepository
	tokens  port.TokenRepository
	mailer  port.Mailer
	captcha port.CaptchaVerifier
	clock   port.Clock
	issuer  port.TokenIssuer
}

func NewRequestPasswordReset(
	users port.UserRepository,
	tokens port.TokenRepository,
	mailer port.Mailer,
	captcha port.CaptchaVerifier,
	clock port.Clock,
	issuer port.TokenIssuer,
) *RequestPasswordReset {
	return &RequestPasswordReset{
		users: users, tokens: tokens, mailer: mailer,
		captcha: captcha, clock: clock, issuer: issuer,
	}
}

type RequestPasswordResetInput struct {
	Email        string
	CaptchaToken string
	RemoteIP     string
}

// Execute always returns nil for unknown emails (no account enumeration).
func (uc *RequestPasswordReset) Execute(ctx context.Context, in RequestPasswordResetInput) error {
	if err := uc.captcha.Verify(ctx, in.CaptchaToken, in.RemoteIP); err != nil {
		return err
	}
	email, err := domain.ParseEmail(in.Email)
	if err != nil {
		return nil
	}
	user, err := uc.users.ByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return nil
		}
		return err
	}
	if err := user.CanAuthenticate(); err != nil {
		return nil
	}

	rawToken, err := crypto.RandomToken(32)
	if err != nil {
		return err
	}
	now := uc.clock.Now()
	token := domain.PasswordResetToken{
		Token:     rawToken,
		UserID:    user.ID,
		ExpiresAt: now.Add(passwordResetTTL),
	}
	if err := uc.tokens.CreatePasswordResetToken(ctx, token, crypto.HashToken(rawToken)); err != nil {
		return err
	}
	resetURL := fmt.Sprintf("%s/reset-password?token=%s", uc.issuer.Issuer(), rawToken)
	return uc.mailer.SendPasswordReset(ctx, email, resetURL)
}

type ResetPassword struct {
	users    port.UserRepository
	tokens   port.TokenRepository
	sessions port.SessionRepository
	hasher   port.PasswordHasher
	clock    port.Clock
}

func NewResetPassword(
	users port.UserRepository,
	tokens port.TokenRepository,
	sessions port.SessionRepository,
	hasher port.PasswordHasher,
	clock port.Clock,
) *ResetPassword {
	return &ResetPassword{users: users, tokens: tokens, sessions: sessions, hasher: hasher, clock: clock}
}

type ResetPasswordInput struct {
	Token           string
	Password        string
	PasswordConfirm string
}

func (uc *ResetPassword) Execute(ctx context.Context, in ResetPasswordInput) error {
	if in.Token == "" {
		return domain.ErrInvalidToken
	}
	if in.Password != in.PasswordConfirm {
		return domain.ValidationError{Field: "password_confirm", Message: "passwords do not match"}
	}
	password, err := domain.NewPlainPassword(in.Password)
	if err != nil {
		return err
	}
	now := uc.clock.Now()
	token, err := uc.tokens.ConsumePasswordResetToken(ctx, crypto.HashToken(in.Token), now)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return domain.ErrInvalidToken
		}
		return err
	}
	hash, err := uc.hasher.Hash(ctx, password)
	if err != nil {
		return err
	}
	if err := uc.users.UpdatePassword(ctx, token.UserID, hash, now); err != nil {
		return err
	}
	return uc.sessions.RevokeAllForUser(ctx, token.UserID, now)
}

type AdminClients struct {
	clients port.ClientRepository
	hasher  port.PasswordHasher
}

func NewAdminClients(clients port.ClientRepository, hasher port.PasswordHasher) *AdminClients {
	return &AdminClients{clients: clients, hasher: hasher}
}

func (uc *AdminClients) List(ctx context.Context) ([]domain.OAuthClient, error) {
	return uc.clients.List(ctx)
}

type CreateClientInput struct {
	ClientID    string
	Name        string
	RedirectURI string
	AccessMode  string
}

type CreateClientResult struct {
	Client       domain.OAuthClient
	ClientSecret string
}

func (uc *AdminClients) Create(ctx context.Context, actor domain.User, in CreateClientInput) (CreateClientResult, error) {
	if !actor.IsAdmin() {
		return CreateClientResult{}, domain.ErrForbidden
	}
	clientID := domain.ClientID(in.ClientID)
	if clientID == "" || in.Name == "" || in.RedirectURI == "" {
		return CreateClientResult{}, domain.ValidationError{Field: "client", Message: "client_id, name and redirect_uri are required"}
	}
	mode, err := domain.ParseAccessMode(in.AccessMode)
	if err != nil {
		return CreateClientResult{}, err
	}
	if _, err := uc.clients.ByClientID(ctx, clientID); err == nil {
		return CreateClientResult{}, domain.ValidationError{Field: "client_id", Message: "client_id already exists"}
	} else if !errors.Is(err, domain.ErrNotFound) {
		return CreateClientResult{}, err
	}
	secret, err := crypto.RandomToken(24)
	if err != nil {
		return CreateClientResult{}, err
	}
	hash, err := uc.hasher.Hash(ctx, domain.PlainPassword(secret))
	if err != nil {
		return CreateClientResult{}, err
	}
	client := domain.OAuthClient{
		ClientID:         clientID,
		ClientSecretHash: hash,
		Name:             in.Name,
		RedirectURIs:     []string{in.RedirectURI},
		AccessMode:       mode,
	}
	if err := uc.clients.Upsert(ctx, client); err != nil {
		return CreateClientResult{}, err
	}
	return CreateClientResult{Client: client, ClientSecret: secret}, nil
}

func (uc *AdminClients) SetAccessMode(ctx context.Context, actor domain.User, clientID string, modeRaw string) error {
	if !actor.IsAdmin() {
		return domain.ErrForbidden
	}
	mode, err := domain.ParseAccessMode(modeRaw)
	if err != nil {
		return err
	}
	return uc.clients.UpdateAccessMode(ctx, domain.ClientID(clientID), mode)
}
