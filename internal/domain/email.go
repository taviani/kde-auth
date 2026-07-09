package domain

import (
	"net/mail"
	"strings"
)

type Email string

func ParseEmail(raw string) (Email, error) {
	normalized := strings.TrimSpace(strings.ToLower(raw))
	if normalized == "" {
		return "", ValidationError{Field: "email", Message: "email is required"}
	}
	addr, err := mail.ParseAddress(normalized)
	if err != nil || addr.Address != normalized {
		return "", ValidationError{Field: "email", Message: "invalid email address"}
	}
	return Email(normalized), nil
}

func (e Email) String() string {
	return string(e)
}
