package handler

import (
	"encoding/json"
	"net/http"

	"github.com/taviani/kde-auth/internal/adapter/http/response"
	"github.com/taviani/kde-auth/internal/domain"
	"github.com/taviani/kde-auth/internal/platform/ratelimit"
	"github.com/taviani/kde-auth/internal/port"
	"github.com/taviani/kde-auth/internal/usecase"
)

type AccountEmails struct {
	uc      *usecase.AccountEmails
	issuer  port.TokenIssuer
	limiter *ratelimit.Limiter
}

func NewAccountEmails(uc *usecase.AccountEmails, issuer port.TokenIssuer, limiter *ratelimit.Limiter) *AccountEmails {
	return &AccountEmails{uc: uc, issuer: issuer, limiter: limiter}
}

func (h *AccountEmails) subject(w http.ResponseWriter, r *http.Request) (domain.UserID, bool) {
	token := bearerToken(r)
	if token == "" {
		response.WriteError(w, domain.ErrUnauthorized)
		return "", false
	}
	claims, err := h.issuer.ParseAccessToken(r.Context(), token)
	if err != nil {
		response.WriteError(w, domain.ErrUnauthorized)
		return "", false
	}
	return domain.UserID(claims.Subject), true
}

func (h *AccountEmails) List(w http.ResponseWriter, r *http.Request) {
	userID, ok := h.subject(w, r)
	if !ok {
		return
	}
	emails, err := h.uc.List(r.Context(), userID)
	if err != nil {
		response.WriteError(w, err)
		return
	}
	response.WriteJSON(w, http.StatusOK, map[string]any{"emails": emails})
}

func (h *AccountEmails) Add(w http.ResponseWriter, r *http.Request) {
	userID, ok := h.subject(w, r)
	if !ok {
		return
	}
	ip := ClientIP(r)
	if h.limiter != nil && h.limiter.TooMany(ip, string(userID)) {
		response.WriteError(w, domain.ErrTooManyAttempts)
		return
	}

	var body struct {
		Email          string `json:"email"`
		CaptchaToken   string `json:"captcha_token"`
		TurnstileToken string `json:"cf-turnstile-response"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		response.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json"})
		return
	}
	captcha := body.CaptchaToken
	if captcha == "" {
		captcha = body.TurnstileToken
	}

	if h.limiter != nil {
		h.limiter.Hit(ip, string(userID))
	}
	if err := h.uc.Add(r.Context(), usecase.AddEmailInput{
		UserID:       userID,
		Email:        body.Email,
		CaptchaToken: captcha,
		RemoteIP:     ip,
	}); err != nil {
		response.WriteError(w, err)
		return
	}
	response.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *AccountEmails) Cancel(w http.ResponseWriter, r *http.Request) {
	userID, ok := h.subject(w, r)
	if !ok {
		return
	}
	if err := h.uc.Cancel(r.Context(), userID); err != nil {
		response.WriteError(w, err)
		return
	}
	response.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *AccountEmails) Delete(w http.ResponseWriter, r *http.Request) {
	userID, ok := h.subject(w, r)
	if !ok {
		return
	}
	var body struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		response.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json"})
		return
	}
	if err := h.uc.Delete(r.Context(), usecase.DeleteEmailInput{
		UserID: userID,
		Email:  body.Email,
	}); err != nil {
		response.WriteError(w, err)
		return
	}
	response.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
