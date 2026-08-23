package handler

import (
	"strings"
	"testing"
)

func TestUsesCustomRedirectScheme(t *testing.T) {
	tests := []struct {
		url  string
		want bool
	}{
		{"app://callback?code=abc&state=xyz", true},
		{"portclos://auth/callback?code=abc", true},
		{"com.portclos.app://oauth?code=abc", true},
		{"https://app.example/callback?code=abc", false},
		{"http://localhost:4322/auth/callback?code=abc", false},
		{"not-a-url", false},
	}
	for _, tt := range tests {
		if got := usesCustomRedirectScheme(tt.url); got != tt.want {
			t.Errorf("usesCustomRedirectScheme(%q) = %v, want %v", tt.url, got, tt.want)
		}
	}
}

func TestIsAndroidUserAgent(t *testing.T) {
	if !isAndroidUserAgent("Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/120.0.0.0 Mobile") {
		t.Fatal("expected android")
	}
	if isAndroidUserAgent("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)") {
		t.Fatal("expected not android")
	}
}

func TestAndroidIntentURL(t *testing.T) {
	got, err := androidIntentURL("portclos://auth/callback?code=abc&state=xyz", "com.example.app")
	if err != nil {
		t.Fatal(err)
	}
	want := "intent://auth/callback?code=abc&state=xyz#Intent;scheme=portclos;package=com.example.app;end"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestAndroidIntentURISkipsWithoutPackage(t *testing.T) {
	raw := "portclos://auth/callback?code=abc"
	got, err := androidIntentURL(raw, "")
	if err != nil || got != raw {
		t.Fatalf("got %q err %v", got, err)
	}
}

func TestAppOpenRedirectURL(t *testing.T) {
	androidUA := "Mozilla/5.0 (Linux; Android 14) Chrome/120.0.0.0 Mobile"
	iosUA := "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)"
	raw := "portclos://auth/callback?code=abc&state=dev"

	intent := appOpenRedirectURL(androidUA, raw, "com.example.app")
	if intent == raw || !usesCustomRedirectScheme(intent) {
		t.Fatalf("expected intent url, got %q", intent)
	}
	if !strings.HasPrefix(intent, "intent://") {
		t.Fatalf("expected intent scheme: %q", intent)
	}

	if got := appOpenRedirectURL(iosUA, raw, "com.example.app"); got != raw {
		t.Fatalf("ios should keep custom scheme: %q", got)
	}
	if got := appOpenRedirectURL(androidUA, raw, ""); got != raw {
		t.Fatalf("android without package should keep custom scheme: %q", got)
	}
}
