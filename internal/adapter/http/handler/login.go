package handler

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/taviani/kde-auth/internal/adapter/http/render"
	"github.com/taviani/kde-auth/internal/adapter/http/response"
	"github.com/taviani/kde-auth/internal/domain"
	"github.com/taviani/kde-auth/internal/platform/ratelimit"
	"github.com/taviani/kde-auth/internal/usecase"
)

type Login struct {
	uc           *usecase.Login
	tickets      *usecase.IssueRegisterTicket
	limiter      *ratelimit.Limiter
	render       *render.Renderer
	turnstileKey string
	cookieSecure bool
}

func NewLogin(uc *usecase.Login, tickets *usecase.IssueRegisterTicket, limiter *ratelimit.Limiter, render *render.Renderer, turnstileKey string, cookieSecure bool) *Login {
	return &Login{uc: uc, tickets: tickets, limiter: limiter, render: render, turnstileKey: turnstileKey, cookieSecure: cookieSecure}
}

func (h *Login) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		data := h.page(r, r.URL.Query().Get("next"), "")
		if r.URL.Query().Get("denied") == "1" {
			data.Error = response.UserFacingMessage(domain.ErrNoAppAccess) + " Sign in with an invited account."
		}
		h.render.HTML(w, "login.html", data)
	case http.MethodPost:
		h.post(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *Login) page(r *http.Request, next, email string) render.PageData {
	data := render.PageData{
		Title:            "Sign in",
		Email:            email,
		Next:             next,
		TurnstileSiteKey: h.turnstileKey,
	}
	if h.tickets == nil {
		return data
	}
	if path, ok := h.tickets.LinkForPublicClient(r.Context(), clientIDFromNext(next)); ok {
		data.RegisterURL = path
	}
	return data
}

func clientIDFromNext(next string) string {
	u, err := url.Parse(next)
	if err != nil || u.IsAbs() || u.Host != "" || u.Path != "/authorize" {
		return ""
	}
	return u.Query().Get("client_id")
}

func (h *Login) post(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	email := r.FormValue("email")
	next := r.FormValue("next")
	data := h.page(r, next, email)

	ipKey := "ip:" + ClientIP(r)
	emailKey := "email:" + strings.ToLower(strings.TrimSpace(email))
	if h.limiter != nil && h.limiter.TooMany(ipKey, emailKey) {
		data.Error = response.UserFacingMessage(domain.ErrTooManyAttempts)
		w.WriteHeader(http.StatusTooManyRequests)
		h.render.HTML(w, "login.html", data)
		return
	}

	result, err := h.uc.Execute(r.Context(), usecase.LoginInput{
		Email:        email,
		Password:     r.FormValue("password"),
		CaptchaToken: r.FormValue("cf-turnstile-response"),
		RemoteIP:     ClientIP(r),
	})
	if err != nil {
		if h.limiter != nil && (errors.Is(err, domain.ErrInvalidCredentials) || errors.Is(err, domain.ErrForbidden)) {
			h.limiter.Hit(ipKey, emailKey)
		}
		data.Error = response.UserFacingMessage(err)
		h.render.HTML(w, "login.html", data)
		return
	}
	if h.limiter != nil {
		h.limiter.Clear(emailKey)
	}

	response.SetSessionCookie(w, result.SessionToken, result.ExpiresAt, h.cookieSecure)
	if next != "" {
		http.Redirect(w, r, next, http.StatusSeeOther)
		return
	}
	if result.User.IsAdmin() {
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
