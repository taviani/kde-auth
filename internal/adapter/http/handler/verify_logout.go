package handler

import (
	"net/http"

	"github.com/taviani/kde-auth/internal/adapter/http/response"
	"github.com/taviani/kde-auth/internal/usecase"
)

type VerifyEmail struct {
	uc *usecase.VerifyEmail
}

func NewVerifyEmail(uc *usecase.VerifyEmail) *VerifyEmail {
	return &VerifyEmail{uc: uc}
}

func (h *VerifyEmail) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if err := h.uc.Execute(r.Context(), token); err != nil {
		response.WriteError(w, err)
		return
	}
	response.WriteJSON(w, http.StatusOK, map[string]string{
		"status":  "verified",
		"message": "Email verified. You can sign in now.",
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
