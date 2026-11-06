package domain

import (
	"errors"
	"testing"
)

func TestParseRedirectURIList(t *testing.T) {
	got, err := ParseRedirectURIList("  https://app.example/callback  \n\napp://cb\r\nhttps://app.example/cb?b=1&a=2\napp://cb\n")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"https://app.example/callback",
		"app://cb",
		"https://app.example/cb?b=1&a=2",
	}
	if len(got) != len(want) {
		t.Fatalf("got %#v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %#v want %#v", got, want)
		}
	}

	custom, err := ParseRedirectURIList("com.example.app:/oauth2redirect")
	if err != nil {
		t.Fatal(err)
	}
	if len(custom) != 1 || custom[0] != "com.example.app:/oauth2redirect" {
		t.Fatalf("got %#v", custom)
	}

	if _, err := ParseRedirectURIList("http://localhost:4322/auth/callback"); err != nil {
		t.Fatal(err)
	}

	cases := []string{
		"",
		" \n\t",
		"not a uri",
		"/relative",
		"https://app.example/cb#frag",
		"javascript:alert(1)",
		"http://",
		"https://app.example/a path",
		"intent://auth/callback#Intent;scheme=app;package=com.example.app;end",
	}
	for _, raw := range cases {
		if _, err := ParseRedirectURIList(raw); err == nil {
			t.Fatalf("expected error for %q", raw)
		} else if !errors.Is(err, ErrValidation) {
			t.Fatalf("expected validation error for %q, got %v", raw, err)
		}
	}
}

func TestParseAndroidPackage(t *testing.T) {
	pkg, err := ParseAndroidPackage("  com.example.app ")
	if err != nil || pkg != "com.example.app" {
		t.Fatalf("got %q err %v", pkg, err)
	}
	if pkg, err := ParseAndroidPackage("  "); err != nil || pkg != "" {
		t.Fatalf("empty: %q err %v", pkg, err)
	}
	for _, raw := range []string{"com", "intent://auth", "com.example.app/extra", "1com.example"} {
		if _, err := ParseAndroidPackage(raw); !errors.Is(err, ErrValidation) {
			t.Fatalf("expected validation error for %q, got %v", raw, err)
		}
	}
}

func TestRedirectURIsText(t *testing.T) {
	c := OAuthClient{RedirectURIs: []string{"https://a.example/cb", "app://cb"}}
	if got := c.RedirectURIsText(); got != "https://a.example/cb\napp://cb" {
		t.Fatalf("got %q", got)
	}
}
