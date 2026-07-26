package handler

import (
	"net/http"

	"github.com/taviani/kde-auth/internal/adapter/http/render"
	"github.com/taviani/kde-auth/internal/adapter/http/response"
	"github.com/taviani/kde-auth/internal/usecase"
)

type ForgotPassword struct {
	uc           *usecase.RequestPasswordReset
	render       *render.Renderer
	turnstileKey string
}

func NewForgotPassword(uc *usecase.RequestPasswordReset, render *render.Renderer, turnstileKey string) *ForgotPassword {
	return &ForgotPassword{uc: uc, render: render, turnstileKey: turnstileKey}
}

func (h *ForgotPassword) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.render.HTML(w, "forgot_password.html", render.PageData{
			Title:            "Forgot password",
			TurnstileSiteKey: h.turnstileKey,
		})
	case http.MethodPost:
		h.post(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *ForgotPassword) post(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	email := r.FormValue("email")
	data := render.PageData{
		Title:            "Forgot password",
		Email:            email,
		TurnstileSiteKey: h.turnstileKey,
	}
	err := h.uc.Execute(r.Context(), usecase.RequestPasswordResetInput{
		Email:        email,
		CaptchaToken: r.FormValue("cf-turnstile-response"),
		RemoteIP:     ClientIP(r),
	})
	if err != nil {
		data.Error = response.UserFacingMessage(err)
		h.render.HTML(w, "forgot_password.html", data)
		return
	}
	h.render.HTML(w, "forgot_password_sent.html", render.PageData{
		Title: "Check your email",
		Email: email,
	})
}

type ResetPassword struct {
	uc     *usecase.ResetPassword
	render *render.Renderer
}

func NewResetPassword(uc *usecase.ResetPassword, render *render.Renderer) *ResetPassword {
	return &ResetPassword{uc: uc, render: render}
}

func (h *ResetPassword) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		token = r.FormValue("token")
	}
	switch r.Method {
	case http.MethodGet:
		if token == "" {
			h.render.HTML(w, "reset_password.html", render.PageData{
				Title: "Reset password",
				Error: "Missing reset token.",
			})
			return
		}
		h.render.HTML(w, "reset_password.html", render.PageData{
			Title: "Reset password",
			Token: token,
		})
	case http.MethodPost:
		h.post(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *ResetPassword) post(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	token := r.FormValue("token")
	data := render.PageData{
		Title: "Reset password",
		Token: token,
	}
	err := h.uc.Execute(r.Context(), usecase.ResetPasswordInput{
		Token:           token,
		Password:        r.FormValue("password"),
		PasswordConfirm: r.FormValue("password_confirm"),
	})
	if err != nil {
		data.Error = response.UserFacingMessage(err)
		h.render.HTML(w, "reset_password.html", data)
		return
	}
	h.render.HTML(w, "reset_password_done.html", render.PageData{
		Title:   "Password updated",
		Success: "Your password has been changed. You can sign in now.",
	})
}
