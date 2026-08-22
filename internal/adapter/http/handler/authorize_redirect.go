package handler

import (
	"net/url"
	"strings"
)

// usesCustomRedirectScheme is true for native app callbacks (app://, com.example.app://, …).
// http/https keep a normal 302 redirect.
func usesCustomRedirectScheme(redirectURL string) bool {
	u, err := url.Parse(redirectURL)
	if err != nil {
		return false
	}
	scheme := strings.ToLower(u.Scheme)
	return scheme != "" && scheme != "http" && scheme != "https"
}
