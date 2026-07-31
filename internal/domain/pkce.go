package domain

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
)

const (
	CodeChallengeMethodS256 = "S256"
)

// VerifyPKCES256 checks code_verifier against a stored S256 code_challenge (RFC 7636).
func VerifyPKCES256(codeChallenge, codeVerifier string) error {
	if codeChallenge == "" || codeVerifier == "" {
		return ErrInvalidGrant
	}
	if len(codeVerifier) < 43 || len(codeVerifier) > 128 {
		return ErrInvalidGrant
	}
	sum := sha256.Sum256([]byte(codeVerifier))
	computed := base64.RawURLEncoding.EncodeToString(sum[:])
	if subtle.ConstantTimeCompare([]byte(computed), []byte(codeChallenge)) != 1 {
		return ErrInvalidGrant
	}
	return nil
}

func ParseCodeChallengeMethod(raw string) (string, error) {
	switch raw {
	case "", CodeChallengeMethodS256:
		return CodeChallengeMethodS256, nil
	default:
		return "", ValidationError{Field: "code_challenge_method", Message: "only S256 is supported"}
	}
}
