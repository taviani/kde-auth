package domain

import "time"

type ClientID string

type AccessMode string

const (
	AccessModePublic     AccessMode = "public"
	AccessModeInviteOnly AccessMode = "invite_only"
)

func ParseAccessMode(raw string) (AccessMode, error) {
	switch AccessMode(raw) {
	case AccessModePublic, AccessModeInviteOnly:
		return AccessMode(raw), nil
	case "":
		return AccessModePublic, nil
	default:
		return "", ValidationError{Field: "access_mode", Message: "must be public or invite_only"}
	}
}

type OAuthClient struct {
	ID               string
	ClientID         ClientID
	ClientSecretHash PasswordHash
	Name             string
	RedirectURIs     []string
	AccessMode       AccessMode
}

func (c OAuthClient) AllowsRedirectURI(uri string) bool {
	for _, allowed := range c.RedirectURIs {
		if allowed == uri {
			return true
		}
	}
	return false
}

func (c OAuthClient) IsInviteOnly() bool {
	return c.AccessMode == AccessModeInviteOnly
}

type Invite struct {
	ID        string
	Token     string // raw token only when newly created
	ClientID  ClientID
	Email     Email
	CreatedBy UserID
	ExpiresAt time.Time
	UsedAt    *time.Time
	RevokedAt *time.Time
	CreatedAt time.Time
}

func (i Invite) IsUsable(at time.Time) bool {
	if i.UsedAt != nil || i.RevokedAt != nil {
		return false
	}
	return at.Before(i.ExpiresAt)
}
