package handler

import (
	"net/http"
	"testing"
)

func TestClientIP(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		remoteAddr string
		realIP     string
		forwarded  string
		want       string
	}{
		{
			name:       "x-real-ip preferred",
			remoteAddr: "10.0.0.1:54321",
			realIP:     "203.0.113.10",
			forwarded:  "198.51.100.1, 10.0.0.1",
			want:       "203.0.113.10",
		},
		{
			name:       "x-forwarded-for first hop",
			remoteAddr: "10.0.0.1:54321",
			forwarded:  "203.0.113.10, 10.0.0.1",
			want:       "203.0.113.10",
		},
		{
			name:       "remote addr without port",
			remoteAddr: "10.0.0.1:54321",
			want:       "10.0.0.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := &http.Request{
				RemoteAddr: tt.remoteAddr,
				Header:     make(http.Header),
			}
			if tt.realIP != "" {
				r.Header.Set("X-Real-IP", tt.realIP)
			}
			if tt.forwarded != "" {
				r.Header.Set("X-Forwarded-For", tt.forwarded)
			}
			if got := ClientIP(r); got != tt.want {
				t.Fatalf("ClientIP() = %q, want %q", got, tt.want)
			}
		})
	}
}
