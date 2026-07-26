package handler

import (
	"net/http"

	"github.com/taviani/kde-auth/internal/adapter/http/render"
	"github.com/taviani/kde-auth/internal/adapter/http/response"
	"github.com/taviani/kde-auth/internal/usecase"
)

type VerifyEmail struct {
	uc     *usecase.VerifyEmail
	render *render.Renderer
}

func NewVerifyEmail(uc *usecase.VerifyEmail, render *render.Renderer) *VerifyEmail {
	return &VerifyEmail{uc: uc, render: render}
}

func (h *VerifyEmail) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if err := h.uc.Execute(r.Context(), token); err != nil {
		h.render.HTML(w, "verify_result.html", render.PageData{
			Title: "Verification failed",
			Error: response.UserFacingMessage(err),
		})
		return
	}
	h.render.HTML(w, "verify_result.html", render.PageData{
		Title:   "Email verified",
		Success: "Your email address has been confirmed.",
	})
}

type Logout struct {
	uc           *usecase.Logout
	cookieSecure bool
}

func NewLogout(uc *usecase.Logout, cookieSecure bool) *Logout {
	return &Logout{uc: uc, cookieSecure: cookieSecure}
}

func (h *Logout) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	_ = h.uc.Execute(r.Context(), response.SessionToken(r))
	response.ClearSessionCookie(w, h.cookieSecure)
	w.WriteHeader(http.StatusNoContent)
}
