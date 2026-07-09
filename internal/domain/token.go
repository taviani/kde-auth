package domain

import "time"

const (
	ScopeOpenID = "openid"
	ScopeEmail  = "email"
)

type AuthorizationCode struct {
	Code        string
	UserID      UserID
	ClientID    ClientID
	RedirectURI string
	Scope       string
	ExpiresAt   time.Time
}

type RefreshToken struct {
	Token     string
	UserID    UserID
	ClientID  ClientID
	ExpiresAt time.Time
}

type EmailVerificationToken struct {
	Token     string
	UserID    UserID
	ExpiresAt time.Time
}

func ParseScope(scope string) error {
	if scope == "" {
		return ValidationError{Field: "scope", Message: "scope is required"}
	}
	hasOpenID := false
	for _, part := range splitFields(scope) {
		switch part {
		case ScopeOpenID:
			hasOpenID = true
		case ScopeEmail:
		default:
			return ErrInvalidScope
		}
	}
	if !hasOpenID {
		return ErrInvalidScope
	}
	return nil
}

func ScopeIncludes(scope, want string) bool {
	for _, part := range splitFields(scope) {
		if part == want {
			return true
		}
	}
	return false
}

func splitFields(s string) []string {
	var parts []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ' ' {
			if i > start {
				parts = append(parts, s[start:i])
			}
			start = i + 1
		}
	}
	return parts
}
