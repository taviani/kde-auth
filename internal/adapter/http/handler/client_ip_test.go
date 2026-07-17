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
			remoteAddr: "172.22.1.1:54321",
			realIP:     "93.9.233.7",
			forwarded:  "1.2.3.4, 172.22.1.1",
			want:       "93.9.233.7",
		},
		{
			name:       "x-forwarded-for first hop",
			remoteAddr: "172.22.1.1:54321",
			forwarded:  "93.9.233.7, 172.22.1.1",
			want:       "93.9.233.7",
		},
		{
			name:       "remote addr without port",
			remoteAddr: "172.22.1.1:54321",
			want:       "172.22.1.1",
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
