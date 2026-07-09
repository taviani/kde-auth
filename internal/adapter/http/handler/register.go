package handler

import (
	"net/http"

	"github.com/taviani/kde-auth/internal/adapter/http/response"
	"github.com/taviani/kde-auth/internal/adapter/http/render"
	"github.com/taviani/kde-auth/internal/usecase"
)

type Register struct {
	uc           *usecase.RegisterUser
	render       *render.Renderer
	turnstileKey string
}

func NewRegister(uc *usecase.RegisterUser, render *render.Renderer, turnstileKey string) *Register {
	return &Register{uc: uc, render: render, turnstileKey: turnstileKey}
}

func (h *Register) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.render.HTML(w, "register.html", render.PageData{
			Title:            "Register",
			TurnstileSiteKey: h.turnstileKey,
		})
	case http.MethodPost:
		h.post(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *Register) post(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	email := r.FormValue("email")
	password := r.FormValue("password")
	confirm := r.FormValue("password_confirm")
	data := render.PageData{
		Title:            "Register",
		Email:            email,
		TurnstileSiteKey: h.turnstileKey,
	}
	if password != confirm {
		data.Error = "Passwords do not match."
		h.render.HTML(w, "register.html", data)
		return
	}

	err := h.uc.Execute(r.Context(), usecase.RegisterInput{
		Email:        email,
		Password:     password,
		CaptchaToken: r.FormValue("cf-turnstile-response"),
		RemoteIP:     r.RemoteAddr,
	})
	if err != nil {
		data.Error = response.UserFacingMessage(err)
		h.render.HTML(w, "register.html", data)
		return
	}
	h.render.HTML(w, "verify_sent.html", render.PageData{
		Title: "Verify email",
		Email: email,
	})
}
