package usecase

import (
	"context"
	"errors"
	"fmt"

	"github.com/taviani/kde-auth/internal/adapter/crypto"
	"github.com/taviani/kde-auth/internal/domain"
	"github.com/taviani/kde-auth/internal/port"
)

type AccountEmails struct {
	users   port.UserRepository
	emails  port.UserEmailRepository
	tokens  port.TokenRepository
	mailer  port.Mailer
	captcha port.CaptchaVerifier
	clock   port.Clock
	issuer  port.TokenIssuer
}

func NewAccountEmails(
	users port.UserRepository,
	emails port.UserEmailRepository,
	tokens port.TokenRepository,
	mailer port.Mailer,
	captcha port.CaptchaVerifier,
	clock port.Clock,
	issuer port.TokenIssuer,
) *AccountEmails {
	return &AccountEmails{
		users: users, emails: emails, tokens: tokens,
		mailer: mailer, captcha: captcha, clock: clock, issuer: issuer,
	}
}

type AccountEmailView struct {
	Email    string `json:"email"`
	Role     string `json:"role"`
	Verified bool   `json:"verified"`
	Pending  bool   `json:"pending"`
}

func (uc *AccountEmails) List(ctx context.Context, userID domain.UserID) ([]AccountEmailView, error) {
	if userID == "" {
		return nil, domain.ErrUnauthorized
	}
	if _, err := uc.users.ByID(ctx, userID); err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return nil, domain.ErrUnauthorized
		}
		return nil, err
	}
	rows, err := uc.emails.ListByUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make([]AccountEmailView, 0, len(rows))
	for _, row := range rows {
		out = append(out, AccountEmailView{
			Email:    row.Email.String(),
			Role:     string(row.Role),
			Verified: row.IsVerified(),
			Pending:  row.IsPending(),
		})
	}
	return out, nil
}

type AddEmailInput struct {
	UserID       domain.UserID
	Email        string
	CaptchaToken string
	RemoteIP     string
}

func (uc *AccountEmails) Add(ctx context.Context, in AddEmailInput) error {
	if in.UserID == "" {
		return domain.ErrUnauthorized
	}
	if err := uc.captcha.Verify(ctx, in.CaptchaToken, in.RemoteIP); err != nil {
		return err
	}
	user, err := uc.users.ByID(ctx, in.UserID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return domain.ErrUnauthorized
		}
		return err
	}
	if err := user.CanAuthorize(); err != nil {
		return err
	}

	email, err := domain.ParseEmail(in.Email)
	if err != nil {
		return err
	}
	if email == user.Email {
		return domain.ErrEmailTaken
	}

	hasSecondary, err := uc.emails.HasSecondary(ctx, in.UserID)
	if err != nil {
		return err
	}
	if hasSecondary {
		return domain.ErrEmailLimitReached
	}

	exists, err := uc.users.ExistsByEmail(ctx, email)
	if err != nil {
		return err
	}
	if exists {
		return domain.ErrEmailTaken
	}

	now := uc.clock.Now()
	if _, err := uc.emails.InsertPendingSecondary(ctx, in.UserID, email, now); err != nil {
		return err
	}

	rawToken, err := crypto.RandomToken(32)
	if err != nil {
		return err
	}
	verifyToken := domain.EmailVerificationToken{
		Token:     rawToken,
		UserID:    in.UserID,
		Email:     email,
		ExpiresAt: now.Add(emailVerifyTTL),
	}
	if err := uc.tokens.CreateEmailVerificationToken(ctx, verifyToken, crypto.HashToken(rawToken)); err != nil {
		return err
	}
	verifyURL := fmt.Sprintf("%s/verify-email?token=%s", uc.issuer.Issuer(), rawToken)
	return uc.mailer.SendVerification(ctx, email, verifyURL)
}

func (uc *AccountEmails) Cancel(ctx context.Context, userID domain.UserID) error {
	if userID == "" {
		return domain.ErrUnauthorized
	}
	if _, err := uc.users.ByID(ctx, userID); err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return domain.ErrUnauthorized
		}
		return err
	}
	return uc.emails.DeletePendingSecondary(ctx, userID)
}

type DeleteEmailInput struct {
	UserID domain.UserID
	Email  string
}

func (uc *AccountEmails) Delete(ctx context.Context, in DeleteEmailInput) error {
	if in.UserID == "" {
		return domain.ErrUnauthorized
	}
	if _, err := uc.users.ByID(ctx, in.UserID); err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return domain.ErrUnauthorized
		}
		return err
	}
	email, err := domain.ParseEmail(in.Email)
	if err != nil {
		return err
	}
	return uc.emails.DeleteVerified(ctx, in.UserID, email, uc.clock.Now())
}
