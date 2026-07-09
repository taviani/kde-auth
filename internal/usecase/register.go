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

const emailVerifyTTL = 24 * time.Hour

type RegisterUser struct {
	users      port.UserRepository
	hasher     port.PasswordHasher
	tokens     port.TokenRepository
	mailer     port.Mailer
	captcha    port.CaptchaVerifier
	clock      port.Clock
	issuer     port.TokenIssuer
	registrationOpen bool
}

func NewRegisterUser(
	users port.UserRepository,
	hasher port.PasswordHasher,
	tokens port.TokenRepository,
	mailer port.Mailer,
	captcha port.CaptchaVerifier,
	clock port.Clock,
	issuer port.TokenIssuer,
	registrationOpen bool,
) *RegisterUser {
	return &RegisterUser{
		users:            users,
		hasher:           hasher,
		tokens:           tokens,
		mailer:           mailer,
		captcha:          captcha,
		clock:            clock,
		issuer:           issuer,
		registrationOpen: registrationOpen,
	}
}

type RegisterInput struct {
	Email        string
	Password     string
	CaptchaToken string
	RemoteIP     string
}

func (uc *RegisterUser) Execute(ctx context.Context, in RegisterInput) error {
	if !uc.registrationOpen {
		return domain.ErrRegistrationClosed
	}
	if err := uc.captcha.Verify(ctx, in.CaptchaToken, in.RemoteIP); err != nil {
		return err
	}

	email, err := domain.ParseEmail(in.Email)
	if err != nil {
		return err
	}
	password, err := domain.NewPlainPassword(in.Password)
	if err != nil {
		return err
	}

	exists, err := uc.users.ExistsByEmail(ctx, email)
	if err != nil {
		return err
	}
	if exists {
		return domain.ErrEmailTaken
	}

	hash, err := uc.hasher.Hash(ctx, password)
	if err != nil {
		return err
	}

	now := uc.clock.Now()
	userID, err := uc.users.Create(ctx, domain.User{
		Email:        email,
		PasswordHash: hash,
		Role:         domain.RoleUser,
		Status:       domain.UserStatusPending,
		CreatedAt:    now,
		UpdatedAt:    now,
	})
	if err != nil {
		return err
	}

	rawToken, err := crypto.RandomToken(32)
	if err != nil {
		return err
	}
	token := domain.EmailVerificationToken{
		Token:     rawToken,
		UserID:    userID,
		ExpiresAt: now.Add(emailVerifyTTL),
	}
	if err := uc.tokens.CreateEmailVerificationToken(ctx, token, crypto.HashToken(rawToken)); err != nil {
		return err
	}

	verifyURL := fmt.Sprintf("%s/verify-email?token=%s", uc.issuer.Issuer(), rawToken)
	return uc.mailer.SendVerification(ctx, email, verifyURL)
}

type VerifyEmail struct {
	users  port.UserRepository
	tokens port.TokenRepository
	clock  port.Clock
}

func NewVerifyEmail(users port.UserRepository, tokens port.TokenRepository, clock port.Clock) *VerifyEmail {
	return &VerifyEmail{users: users, tokens: tokens, clock: clock}
}

func (uc *VerifyEmail) Execute(ctx context.Context, rawToken string) error {
	if rawToken == "" {
		return domain.ErrInvalidToken
	}
	now := uc.clock.Now()
	token, err := uc.tokens.ConsumeEmailVerificationToken(ctx, crypto.HashToken(rawToken), now)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return domain.ErrInvalidToken
		}
		return err
	}
	return uc.users.MarkEmailVerified(ctx, token.UserID, now)
}
