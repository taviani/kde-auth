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

const (
	emailVerifyTTL        = 24 * time.Hour
	registrationTicketTTL = 10 * time.Minute
)

type IssueRegisterTicket struct {
	clients          port.ClientRepository
	tickets          port.RegistrationTicketRepository
	hasher           port.PasswordHasher
	issuer           port.TokenIssuer
	clock            port.Clock
	registrationOpen bool
}

func NewIssueRegisterTicket(
	clients port.ClientRepository,
	tickets port.RegistrationTicketRepository,
	hasher port.PasswordHasher,
	issuer port.TokenIssuer,
	clock port.Clock,
	registrationOpen bool,
) *IssueRegisterTicket {
	return &IssueRegisterTicket{
		clients:          clients,
		tickets:          tickets,
		hasher:           hasher,
		issuer:           issuer,
		clock:            clock,
		registrationOpen: registrationOpen,
	}
}

type IssueRegisterTicketInput struct {
	ClientID     string
	ClientSecret string
}

type IssueRegisterTicketResult struct {
	Ticket      string
	ExpiresIn   int
	RegisterURL string
}

func (uc *IssueRegisterTicket) Execute(ctx context.Context, in IssueRegisterTicketInput) (IssueRegisterTicketResult, error) {
	if !uc.registrationOpen {
		return IssueRegisterTicketResult{}, domain.ErrRegistrationClosed
	}
	client, err := uc.clients.ByClientID(ctx, domain.ClientID(in.ClientID))
	if err != nil {
		return IssueRegisterTicketResult{}, domain.ErrInvalidClient
	}
	if client.IsPublic() {
		return IssueRegisterTicketResult{}, domain.ErrInvalidClient
	}
	if in.ClientSecret == "" || !uc.hasher.Verify(client.ClientSecretHash, domain.PlainPassword(in.ClientSecret)) {
		return IssueRegisterTicketResult{}, domain.ErrInvalidClient
	}
	if client.IsInviteOnly() {
		return IssueRegisterTicketResult{}, domain.ErrInviteOnlyRegistration
	}

	raw, err := crypto.RandomToken(32)
	if err != nil {
		return IssueRegisterTicketResult{}, err
	}
	now := uc.clock.Now()
	expiresAt := now.Add(registrationTicketTTL)
	if err := uc.tickets.Create(ctx, domain.RegistrationTicket{
		ClientID:  client.ClientID,
		ExpiresAt: expiresAt,
	}, crypto.HashToken(raw)); err != nil {
		return IssueRegisterTicketResult{}, err
	}
	return IssueRegisterTicketResult{
		Ticket:      raw,
		ExpiresIn:   int(registrationTicketTTL.Seconds()),
		RegisterURL: fmt.Sprintf("%s/register?ticket=%s", uc.issuer.Issuer(), raw),
	}, nil
}

type RegisterUser struct {
	users            port.UserRepository
	tickets          port.RegistrationTicketRepository
	accesses         port.AppAccessRepository
	hasher           port.PasswordHasher
	tokens           port.TokenRepository
	mailer           port.Mailer
	captcha          port.CaptchaVerifier
	clock            port.Clock
	issuer           port.TokenIssuer
	registrationOpen bool
}

func NewRegisterUser(
	users port.UserRepository,
	tickets port.RegistrationTicketRepository,
	accesses port.AppAccessRepository,
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
		tickets:          tickets,
		accesses:         accesses,
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
	Ticket       string
}

func (uc *RegisterUser) PeekTicket(ctx context.Context, rawTicket string) (domain.RegistrationTicket, error) {
	if !uc.registrationOpen {
		return domain.RegistrationTicket{}, domain.ErrRegistrationClosed
	}
	if rawTicket == "" {
		return domain.RegistrationTicket{}, domain.ErrInvalidToken
	}
	ticket, err := uc.tickets.Peek(ctx, crypto.HashToken(rawTicket), uc.clock.Now())
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return domain.RegistrationTicket{}, domain.ErrInvalidToken
		}
		return domain.RegistrationTicket{}, err
	}
	return ticket, nil
}

func (uc *RegisterUser) Execute(ctx context.Context, in RegisterInput) error {
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

	ticket, err := uc.PeekTicket(ctx, in.Ticket)
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
	consumed, err := uc.tickets.Consume(ctx, crypto.HashToken(in.Ticket), now)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return domain.ErrInvalidToken
		}
		return err
	}
	if consumed.ClientID != ticket.ClientID {
		return domain.ErrInvalidToken
	}

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

	if err := uc.accesses.Upsert(ctx, domain.UserAppAccess{
		UserID:      userID,
		ClientID:    consumed.ClientID,
		EntryDomain: "",
		FirstSeenAt: now,
		LastSeenAt:  now,
	}); err != nil {
		return err
	}

	rawToken, err := crypto.RandomToken(32)
	if err != nil {
		return err
	}
	verifyToken := domain.EmailVerificationToken{
		Token:     rawToken,
		UserID:    userID,
		ExpiresAt: now.Add(emailVerifyTTL),
	}
	if err := uc.tokens.CreateEmailVerificationToken(ctx, verifyToken, crypto.HashToken(rawToken)); err != nil {
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
