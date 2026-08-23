package handler

import (
	"fmt"
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

func isAndroidUserAgent(userAgent string) bool {
	return strings.Contains(strings.ToLower(userAgent), "android")
}

// androidIntentURL converts portclos://auth/callback?… into an intent:// link that
// Chrome Custom Tabs can hand off to the installed app.
func androidIntentURL(customRedirect, androidPackage string) (string, error) {
	if androidPackage == "" {
		return customRedirect, nil
	}
	u, err := url.Parse(customRedirect)
	if err != nil {
		return "", err
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme == "" || scheme == "http" || scheme == "https" {
		return customRedirect, nil
	}

	var target strings.Builder
	target.WriteString("intent://")
	if u.Host != "" {
		target.WriteString(u.Host)
	}
	target.WriteString(u.Path)
	if u.RawQuery != "" {
		target.WriteString("?")
		target.WriteString(u.RawQuery)
	}
	target.WriteString(fmt.Sprintf("#Intent;scheme=%s;package=%s;end", u.Scheme, androidPackage))
	return target.String(), nil
}

func appOpenRedirectURL(userAgent, customRedirect, androidPackage string) string {
	if !usesCustomRedirectScheme(customRedirect) {
		return customRedirect
	}
	if isAndroidUserAgent(userAgent) && androidPackage != "" {
		if intent, err := androidIntentURL(customRedirect, androidPackage); err == nil {
			return intent
		}
	}
	return customRedirect
}
