package handler

import "testing"

func TestUsesCustomRedirectScheme(t *testing.T) {
	tests := []struct {
		url  string
		want bool
	}{
		{"app://callback?code=abc&state=xyz", true},
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
