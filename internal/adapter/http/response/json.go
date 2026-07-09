package response

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/taviani/kde-auth/internal/domain"
)

const SessionCookieName = "kde_session"

func WriteJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func WriteError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, domain.ErrInvalidCredentials),
		errors.Is(err, domain.ErrUnauthorized),
		errors.Is(err, domain.ErrInvalidToken):
		WriteJSON(w, http.StatusUnauthorized, oauthError("invalid_request", err.Error()))
	case errors.Is(err, domain.ErrForbidden):
		WriteJSON(w, http.StatusForbidden, oauthError("access_denied", err.Error()))
	case errors.Is(err, domain.ErrInvalidClient):
		WriteJSON(w, http.StatusUnauthorized, oauthError("invalid_client", err.Error()))
	case errors.Is(err, domain.ErrInvalidGrant):
		WriteJSON(w, http.StatusBadRequest, oauthError("invalid_grant", err.Error()))
	case errors.Is(err, domain.ErrEmailTaken):
		WriteJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
	case errors.Is(err, domain.ErrRegistrationClosed):
		WriteJSON(w, http.StatusForbidden, map[string]string{"error": err.Error()})
	default:
		var v domain.ValidationError
		if errors.As(err, &v) {
			WriteJSON(w, http.StatusBadRequest, map[string]string{"error": v.Error(), "field": v.Field})
			return
		}
		WriteJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
}

func oauthError(code, description string) map[string]string {
	return map[string]string{"error": code, "error_description": description}
}

func UserFacingMessage(err error) string {
	switch {
	case errors.Is(err, domain.ErrInvalidCredentials):
		return "Invalid email or password."
	case errors.Is(err, domain.ErrEmailTaken):
		return "An account with this email already exists."
	case errors.Is(err, domain.ErrRegistrationClosed):
		return "Registration is currently closed."
	case errors.Is(err, domain.ErrCaptchaFailed):
		return "Captcha verification failed. Please try again."
	case errors.Is(err, domain.ErrForbidden):
		return "Please verify your email before signing in."
	default:
		var v domain.ValidationError
		if errors.As(err, &v) {
			return v.Message
		}
		return "Something went wrong. Please try again."
	}
}

func SetSessionCookie(w http.ResponseWriter, token string, expiresAt time.Time, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		Expires:  expiresAt,
	})
}

func ClearSessionCookie(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

func SessionToken(r *http.Request) string {
	c, err := r.Cookie(SessionCookieName)
	if err != nil {
		return ""
	}
	return c.Value
}
