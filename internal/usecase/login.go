package usecase

import (
	"context"
	"errors"
	"time"

	"github.com/taviani/kde-auth/internal/adapter/crypto"
	"github.com/taviani/kde-auth/internal/domain"
	"github.com/taviani/kde-auth/internal/port"
)

type Login struct {
	users    port.UserRepository
	sessions port.SessionRepository
	hasher   port.PasswordHasher
	captcha  port.CaptchaVerifier
	clock    port.Clock
	sessionTTL time.Duration
}

func NewLogin(
	users port.UserRepository,
	sessions port.SessionRepository,
	hasher port.PasswordHasher,
	captcha port.CaptchaVerifier,
	clock port.Clock,
	sessionTTL time.Duration,
) *Login {
	return &Login{
		users:      users,
		sessions:   sessions,
		hasher:     hasher,
		captcha:    captcha,
		clock:      clock,
		sessionTTL: sessionTTL,
	}
}

type LoginInput struct {
	Email        string
	Password     string
	CaptchaToken string
	RemoteIP     string
}

type LoginResult struct {
	SessionToken string
	ExpiresAt    time.Time
}

func (uc *Login) Execute(ctx context.Context, in LoginInput) (LoginResult, error) {
	if err := uc.captcha.Verify(ctx, in.CaptchaToken, in.RemoteIP); err != nil {
		return LoginResult{}, err
	}

	email, err := domain.ParseEmail(in.Email)
	if err != nil {
		return LoginResult{}, domain.ErrInvalidCredentials
	}
	if in.Password == "" {
		return LoginResult{}, domain.ErrInvalidCredentials
	}
	password := domain.PlainPassword(in.Password)

	user, err := uc.users.ByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return LoginResult{}, domain.ErrInvalidCredentials
		}
		return LoginResult{}, err
	}
	if err := user.CanAuthenticate(); err != nil {
		return LoginResult{}, domain.ErrInvalidCredentials
	}
	if !uc.hasher.Verify(user.PasswordHash, password) {
		return LoginResult{}, domain.ErrInvalidCredentials
	}
	if !user.IsEmailVerified() {
		return LoginResult{}, domain.ErrForbidden
	}

	rawToken, err := crypto.RandomToken(32)
	if err != nil {
		return LoginResult{}, err
	}
	now := uc.clock.Now()
	expiresAt := now.Add(uc.sessionTTL)
	session := domain.Session{
		UserID:    user.ID,
		ExpiresAt: expiresAt,
	}
	if err := uc.sessions.Create(ctx, session, crypto.HashToken(rawToken)); err != nil {
		return LoginResult{}, err
	}
	return LoginResult{SessionToken: rawToken, ExpiresAt: expiresAt}, nil
}

type Logout struct {
	sessions port.SessionRepository
	clock    port.Clock
}

func NewLogout(sessions port.SessionRepository, clock port.Clock) *Logout {
	return &Logout{sessions: sessions, clock: clock}
}

func (uc *Logout) Execute(ctx context.Context, sessionToken string) error {
	if sessionToken == "" {
		return nil
	}
	return uc.sessions.Revoke(ctx, crypto.HashToken(sessionToken), uc.clock.Now())
}

type ResolveSession struct {
	sessions port.SessionRepository
	users    port.UserRepository
	clock    port.Clock
}

func NewResolveSession(sessions port.SessionRepository, users port.UserRepository, clock port.Clock) *ResolveSession {
	return &ResolveSession{sessions: sessions, users: users, clock: clock}
}

func (uc *ResolveSession) Execute(ctx context.Context, sessionToken string) (domain.User, error) {
	if sessionToken == "" {
		return domain.User{}, domain.ErrUnauthorized
	}
	session, err := uc.sessions.ByTokenHash(ctx, crypto.HashToken(sessionToken), uc.clock.Now())
	if err != nil {
		return domain.User{}, domain.ErrUnauthorized
	}
	user, err := uc.users.ByID(ctx, session.UserID)
	if err != nil {
		return domain.User{}, domain.ErrUnauthorized
	}
	if err := user.CanAuthorize(); err != nil {
		return domain.User{}, domain.ErrUnauthorized
	}
	return user, nil
}
