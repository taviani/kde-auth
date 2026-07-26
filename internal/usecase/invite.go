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

const inviteTTL = 14 * 24 * time.Hour

type AdminInvites struct {
	invites port.InviteRepository
	clients port.ClientRepository
	mailer  port.Mailer
	issuer  port.TokenIssuer
	clock   port.Clock
}

func NewAdminInvites(
	invites port.InviteRepository,
	clients port.ClientRepository,
	mailer port.Mailer,
	issuer port.TokenIssuer,
	clock port.Clock,
) *AdminInvites {
	return &AdminInvites{
		invites: invites,
		clients: clients,
		mailer:  mailer,
		issuer:  issuer,
		clock:   clock,
	}
}

type CreateInviteInput struct {
	ClientID string
	Email    string
}

type CreateInviteResult struct {
	Invite    domain.Invite
	AcceptURL string
}

func (uc *AdminInvites) Create(ctx context.Context, actor domain.User, in CreateInviteInput) (CreateInviteResult, error) {
	if !actor.IsAdmin() {
		return CreateInviteResult{}, domain.ErrForbidden
	}
	email, err := domain.ParseEmail(in.Email)
	if err != nil {
		return CreateInviteResult{}, err
	}
	client, err := uc.clients.ByClientID(ctx, domain.ClientID(in.ClientID))
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return CreateInviteResult{}, domain.ValidationError{Field: "client_id", Message: "unknown client"}
		}
		return CreateInviteResult{}, err
	}
	raw, err := crypto.RandomToken(32)
	if err != nil {
		return CreateInviteResult{}, err
	}
	now := uc.clock.Now()
	invite := domain.Invite{
		ClientID:  client.ClientID,
		Email:     email,
		CreatedBy: actor.ID,
		ExpiresAt: now.Add(inviteTTL),
		CreatedAt: now,
	}
	if err := uc.invites.Create(ctx, invite, crypto.HashToken(raw)); err != nil {
		return CreateInviteResult{}, err
	}
	invite.Token = raw
	acceptURL := fmt.Sprintf("%s/invite?token=%s", uc.issuer.Issuer(), raw)
	_ = uc.mailer.SendInvite(ctx, email, client.Name, acceptURL)
	return CreateInviteResult{Invite: invite, AcceptURL: acceptURL}, nil
}

func (uc *AdminInvites) List(ctx context.Context, clientID domain.ClientID) ([]domain.Invite, error) {
	if clientID == "" {
		return nil, nil
	}
	return uc.invites.ListByClient(ctx, clientID)
}

func (uc *AdminInvites) Revoke(ctx context.Context, actor domain.User, inviteID string) error {
	if !actor.IsAdmin() {
		return domain.ErrForbidden
	}
	if inviteID == "" {
		return domain.ValidationError{Field: "invite_id", Message: "required"}
	}
	return uc.invites.Revoke(ctx, inviteID, uc.clock.Now())
}

type AcceptInvite struct {
	invites  port.InviteRepository
	clients  port.ClientRepository
	users    port.UserRepository
	accesses port.AppAccessRepository
	hasher   port.PasswordHasher
	tokens   port.TokenRepository
	mailer   port.Mailer
	captcha  port.CaptchaVerifier
	sessions *ResolveSession
	issuer   port.TokenIssuer
	clock    port.Clock
}

func NewAcceptInvite(
	invites port.InviteRepository,
	clients port.ClientRepository,
	users port.UserRepository,
	accesses port.AppAccessRepository,
	hasher port.PasswordHasher,
	tokens port.TokenRepository,
	mailer port.Mailer,
	captcha port.CaptchaVerifier,
	sessions *ResolveSession,
	issuer port.TokenIssuer,
	clock port.Clock,
) *AcceptInvite {
	return &AcceptInvite{
		invites:  invites,
		clients:  clients,
		users:    users,
		accesses: accesses,
		hasher:   hasher,
		tokens:   tokens,
		mailer:   mailer,
		captcha:  captcha,
		sessions: sessions,
		issuer:   issuer,
		clock:    clock,
	}
}

type InvitePreview struct {
	Invite       domain.Invite
	Client       domain.OAuthClient
	UserExists   bool
	LoggedIn     bool
	EmailMatches bool
	AlreadyHas   bool
}

func (uc *AcceptInvite) Preview(ctx context.Context, rawToken, sessionToken string) (InvitePreview, error) {
	invite, client, err := uc.loadUsable(ctx, rawToken)
	if err != nil {
		return InvitePreview{}, err
	}
	preview := InvitePreview{Invite: invite, Client: client}
	_, err = uc.users.ByEmail(ctx, invite.Email)
	if err == nil {
		preview.UserExists = true
	} else if !errors.Is(err, domain.ErrNotFound) {
		return InvitePreview{}, err
	}
	if sessionToken != "" {
		user, err := uc.sessions.Execute(ctx, sessionToken)
		if err == nil {
			preview.LoggedIn = true
			preview.EmailMatches = user.Email == invite.Email
			if preview.EmailMatches {
				has, err := uc.accesses.HasAccess(ctx, user.ID, client.ClientID)
				if err != nil {
					return InvitePreview{}, err
				}
				preview.AlreadyHas = has
			}
		}
	}
	return preview, nil
}

func (uc *AcceptInvite) AcceptExisting(ctx context.Context, rawToken, sessionToken string) error {
	invite, client, err := uc.loadUsable(ctx, rawToken)
	if err != nil {
		return err
	}
	user, err := uc.sessions.Execute(ctx, sessionToken)
	if err != nil {
		return domain.ErrUnauthorized
	}
	if user.Email != invite.Email {
		return domain.ValidationError{Field: "email", Message: "sign in with the invited email address"}
	}
	now := uc.clock.Now()
	if err := uc.grant(ctx, user.ID, client.ClientID, now); err != nil {
		return err
	}
	return uc.invites.Consume(ctx, invite.ID, now)
}

type RegisterViaInviteInput struct {
	Token        string
	Password     string
	CaptchaToken string
	RemoteIP     string
}

func (uc *AcceptInvite) Register(ctx context.Context, in RegisterViaInviteInput) error {
	invite, client, err := uc.loadUsable(ctx, in.Token)
	if err != nil {
		return err
	}
	if err := uc.captcha.Verify(ctx, in.CaptchaToken, in.RemoteIP); err != nil {
		return err
	}
	password, err := domain.NewPlainPassword(in.Password)
	if err != nil {
		return err
	}
	exists, err := uc.users.ExistsByEmail(ctx, invite.Email)
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
		Email:        invite.Email,
		PasswordHash: hash,
		Role:         domain.RoleUser,
		Status:       domain.UserStatusPending,
		CreatedAt:    now,
		UpdatedAt:    now,
	})
	if err != nil {
		return err
	}
	if err := uc.grant(ctx, userID, client.ClientID, now); err != nil {
		return err
	}
	if err := uc.invites.Consume(ctx, invite.ID, now); err != nil {
		return err
	}
	rawVerify, err := crypto.RandomToken(32)
	if err != nil {
		return err
	}
	verifyToken := domain.EmailVerificationToken{
		Token:     rawVerify,
		UserID:    userID,
		ExpiresAt: now.Add(emailVerifyTTL),
	}
	if err := uc.tokens.CreateEmailVerificationToken(ctx, verifyToken, crypto.HashToken(rawVerify)); err != nil {
		return err
	}
	verifyURL := fmt.Sprintf("%s/verify-email?token=%s", uc.issuer.Issuer(), rawVerify)
	return uc.mailer.SendVerification(ctx, invite.Email, verifyURL)
}

func (uc *AcceptInvite) loadUsable(ctx context.Context, rawToken string) (domain.Invite, domain.OAuthClient, error) {
	if rawToken == "" {
		return domain.Invite{}, domain.OAuthClient{}, domain.ErrInvalidToken
	}
	invite, err := uc.invites.ByTokenHash(ctx, crypto.HashToken(rawToken))
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return domain.Invite{}, domain.OAuthClient{}, domain.ErrInvalidToken
		}
		return domain.Invite{}, domain.OAuthClient{}, err
	}
	now := uc.clock.Now()
	if !invite.IsUsable(now) {
		return domain.Invite{}, domain.OAuthClient{}, domain.ErrInvalidToken
	}
	client, err := uc.clients.ByClientID(ctx, invite.ClientID)
	if err != nil {
		return domain.Invite{}, domain.OAuthClient{}, err
	}
	return invite, client, nil
}

func (uc *AcceptInvite) grant(ctx context.Context, userID domain.UserID, clientID domain.ClientID, at time.Time) error {
	return uc.accesses.Upsert(ctx, domain.UserAppAccess{
		UserID:      userID,
		ClientID:    clientID,
		EntryDomain: "",
		FirstSeenAt: at,
		LastSeenAt:  at,
	})
}
