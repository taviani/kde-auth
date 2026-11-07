package handler

import (
	"net/http"

	"github.com/taviani/kde-auth/internal/adapter/http/render"
	"github.com/taviani/kde-auth/internal/adapter/http/response"
	"github.com/taviani/kde-auth/internal/domain"
	"github.com/taviani/kde-auth/internal/port"
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
	clients      port.ClientRepository
	cookieSecure bool
}

func NewLogout(uc *usecase.Logout, clients port.ClientRepository, cookieSecure bool) *Logout {
	return &Logout{uc: uc, clients: clients, cookieSecure: cookieSecure}
}

func (h *Logout) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	redirect, pkg := h.allowedReturn(r)
	_ = h.uc.Execute(r.Context(), response.SessionToken(r))
	response.ClearSessionCookie(w, h.cookieSecure)
	if redirect == "" {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	target := redirect
	if usesCustomRedirectScheme(target) {
		target = appOpenRedirectURL(r.UserAgent(), target, pkg)
	}
	http.Redirect(w, r, target, http.StatusFound)
}

func (h *Logout) allowedReturn(r *http.Request) (string, string) {
	if r.Method != http.MethodGet || h.clients == nil {
		return "", ""
	}
	clientID := r.URL.Query().Get("client_id")
	redirectURI := r.URL.Query().Get("redirect_uri")
	if clientID == "" || redirectURI == "" {
		return "", ""
	}
	client, err := h.clients.ByClientID(r.Context(), domain.ClientID(clientID))
	if err != nil || !client.AllowsRedirectURI(redirectURI) {
		return "", ""
	}
	return redirectURI, client.AndroidPackage
}
