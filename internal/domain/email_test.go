package domain_test

import (
	"errors"
	"testing"

	"github.com/taviani/kde-auth/internal/domain"
)

func TestParseEmail(t *testing.T) {
	email, err := domain.ParseEmail("  User@Example.COM ")
	if err != nil {
		t.Fatal(err)
	}
	if email.String() != "user@example.com" {
		t.Fatalf("got %q", email)
	}
}

func TestParseScope(t *testing.T) {
	if err := domain.ParseScope("openid email"); err != nil {
		t.Fatal(err)
	}
	if err := domain.ParseScope("email"); !errors.Is(err, domain.ErrInvalidScope) {
		t.Fatalf("expected invalid scope, got %v", err)
	}
}
