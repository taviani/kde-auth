package domain

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
)

type ClientID string

type AccessMode string

const (
	AccessModePublic     AccessMode = "public"
	AccessModeInviteOnly AccessMode = "invite_only"
)

type TokenEndpointAuthMethod string

const (
	TokenAuthClientSecretPost TokenEndpointAuthMethod = "client_secret_post"
	TokenAuthNone             TokenEndpointAuthMethod = "none"
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

func ParseTokenEndpointAuthMethod(raw string) (TokenEndpointAuthMethod, error) {
	switch TokenEndpointAuthMethod(raw) {
	case TokenAuthClientSecretPost, TokenAuthNone:
		return TokenEndpointAuthMethod(raw), nil
	case "":
		return TokenAuthClientSecretPost, nil
	default:
		return "", ValidationError{Field: "token_endpoint_auth_method", Message: "must be client_secret_post or none"}
	}
}

type OAuthClient struct {
	ID                      string
	ClientID                ClientID
	ClientSecretHash        PasswordHash
	Name                    string
	RedirectURIs            []string
	AccessMode              AccessMode
	TokenEndpointAuthMethod TokenEndpointAuthMethod
	AndroidPackage          string // Play package for intent:// deep links from Custom Tabs
}

func (c OAuthClient) AllowsRedirectURI(uri string) bool {
	for _, allowed := range c.RedirectURIs {
		if allowed == uri {
			return true
		}
	}
	return false
}

// RedirectURIsText is the exact-match list, one URI per line.
func (c OAuthClient) RedirectURIsText() string {
	return strings.Join(c.RedirectURIs, "\n")
}

// ParseRedirectURIList accepts one absolute URI per line. Blank lines are ignored.
// The stored value is the trimmed input, so matching stays exact.
func ParseRedirectURIList(raw string) ([]string, error) {
	var out []string
	seen := make(map[string]struct{})
	for _, line := range strings.Split(raw, "\n") {
		uri := strings.TrimSpace(line)
		if uri == "" {
			continue
		}
		if err := validateRedirectURI(uri); err != nil {
			return nil, err
		}
		if _, ok := seen[uri]; ok {
			continue
		}
		seen[uri] = struct{}{}
		out = append(out, uri)
	}
	if len(out) == 0 {
		return nil, ValidationError{Field: "redirect_uris", Message: "at least one redirect URI is required"}
	}
	return out, nil
}

func validateRedirectURI(uri string) error {
	if strings.ContainsAny(uri, " \t") {
		return ValidationError{Field: "redirect_uris", Message: fmt.Sprintf("redirect URI must be absolute: %q", uri)}
	}
	u, err := url.Parse(uri)
	if err != nil || !u.IsAbs() || (u.Host == "" && u.Opaque == "" && u.Path == "") {
		return ValidationError{Field: "redirect_uris", Message: fmt.Sprintf("redirect URI must be absolute: %q", uri)}
	}
	if u.Fragment != "" {
		return ValidationError{Field: "redirect_uris", Message: fmt.Sprintf("redirect URI must not include a fragment: %q", uri)}
	}
	switch strings.ToLower(u.Scheme) {
	case "intent":
		return ValidationError{Field: "redirect_uris", Message: fmt.Sprintf("register the app scheme, not an intent:// link: %q", uri)}
	case "javascript", "data", "file", "blob", "vbscript":
		return ValidationError{Field: "redirect_uris", Message: fmt.Sprintf("redirect URI scheme is not allowed: %q", uri)}
	case "http", "https":
		if u.Host == "" {
			return ValidationError{Field: "redirect_uris", Message: fmt.Sprintf("redirect URI must be absolute: %q", uri)}
		}
	}
	return nil
}

var androidPackagePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$`)

// ParseAndroidPackage accepts an empty value. A set value is the Play package
// used to build the Android intent:// handoff. iOS does not use it.
func ParseAndroidPackage(raw string) (string, error) {
	pkg := strings.TrimSpace(raw)
	if pkg == "" {
		return "", nil
	}
	if !androidPackagePattern.MatchString(pkg) {
		return "", ValidationError{Field: "android_package", Message: fmt.Sprintf("Android package must look like com.example.app: %q", pkg)}
	}
	return pkg, nil
}

func (c OAuthClient) IsInviteOnly() bool {
	return c.AccessMode == AccessModeInviteOnly
}

func (c OAuthClient) IsPublic() bool {
	return c.TokenEndpointAuthMethod == TokenAuthNone
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
