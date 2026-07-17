package handler

import (
	"net/http"

	"github.com/taviani/kde-auth/internal/adapter/http/response"
	"github.com/taviani/kde-auth/internal/adapter/http/render"
	"github.com/taviani/kde-auth/internal/usecase"
)

type Login struct {
	uc           *usecase.Login
	render       *render.Renderer
	turnstileKey string
	cookieSecure bool
}

func NewLogin(uc *usecase.Login, render *render.Renderer, turnstileKey string, cookieSecure bool) *Login {
	return &Login{uc: uc, render: render, turnstileKey: turnstileKey, cookieSecure: cookieSecure}
}

func (h *Login) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.render.HTML(w, "login.html", render.PageData{
			Title:            "Sign in",
			Next:             r.URL.Query().Get("next"),
			TurnstileSiteKey: h.turnstileKey,
		})
	case http.MethodPost:
		h.post(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *Login) post(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	email := r.FormValue("email")
	next := r.FormValue("next")
	data := render.PageData{
		Title:            "Sign in",
		Email:            email,
		Next:             next,
		TurnstileSiteKey: h.turnstileKey,
	}

	result, err := h.uc.Execute(r.Context(), usecase.LoginInput{
		Email:        email,
		Password:     r.FormValue("password"),
		CaptchaToken: r.FormValue("cf-turnstile-response"),
		RemoteIP:     ClientIP(r),
	})
	if err != nil {
		data.Error = response.UserFacingMessage(err)
		h.render.HTML(w, "login.html", data)
		return
	}

	response.SetSessionCookie(w, result.SessionToken, result.ExpiresAt, h.cookieSecure)
	if next != "" {
		http.Redirect(w, r, next, http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
