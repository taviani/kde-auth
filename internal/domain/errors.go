package domain

import "errors"

var (
	ErrNotFound               = errors.New("not found")
	ErrInvalidCredentials     = errors.New("invalid credentials")
	ErrEmailTaken             = errors.New("email already registered")
	ErrRegistrationClosed     = errors.New("registration is closed")
	ErrInviteOnlyRegistration = errors.New("this application is invite-only")
	ErrTooManyAttempts        = errors.New("too many attempts")
	ErrInvalidRedirectURI     = errors.New("invalid redirect uri")
	ErrInvalidClient          = errors.New("invalid client")
	ErrInvalidGrant           = errors.New("invalid grant")
	ErrInvalidScope           = errors.New("invalid scope")
	ErrUnauthorized           = errors.New("unauthorized")
	ErrForbidden              = errors.New("forbidden")
	ErrNoAppAccess            = errors.New("no access to this application")
	ErrInvalidToken           = errors.New("invalid token")
	ErrCaptchaFailed          = errors.New("captcha verification failed")
	ErrValidation             = errors.New("validation failed")
)

type ValidationError struct {
	Field   string
	Message string
}

func (e ValidationError) Error() string {
	return e.Message
}

func (e ValidationError) Is(target error) bool {
	return target == ErrValidation
}
