package handler

import (
	"net"
	"net/http"
	"strings"
)

// ClientIP returns the visitor IP behind a trusted reverse proxy.
// Prefers X-Real-IP (set by mailcow nginx), then the first X-Forwarded-For hop,
// then RemoteAddr without the port.
func ClientIP(r *http.Request) string {
	if ip := strings.TrimSpace(r.Header.Get("X-Real-IP")); ip != "" {
		return ip
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ip, _, _ := strings.Cut(xff, ",")
		return strings.TrimSpace(ip)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
