package handler

import (
	"net/http"
	"net/url"

	"github.com/taviani/kde-auth/internal/adapter/http/render"
	"github.com/taviani/kde-auth/internal/adapter/http/response"
	"github.com/taviani/kde-auth/internal/usecase"
)

type Invite struct {
	uc           *usecase.AcceptInvite
	render       *render.Renderer
	turnstileKey string
}

func NewInvite(uc *usecase.AcceptInvite, render *render.Renderer, turnstileKey string) *Invite {
	return &Invite{uc: uc, render: render, turnstileKey: turnstileKey}
}

type invitePageData struct {
	Title            string
	Error            string
	Success          string
	Token            string
	Email            string
	AppName          string
	ClientID         string
	UserExists       bool
	LoggedIn         bool
	EmailMatches     bool
	AlreadyHas       bool
	LoginNext        string
	TurnstileSiteKey string
}

func (h *Invite) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.get(w, r)
	case http.MethodPost:
		h.post(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *Invite) get(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	preview, err := h.uc.Preview(r.Context(), token, response.SessionToken(r))
	if err != nil {
		h.render.HTMLData(w, "invite.html", invitePageData{
			Title: "Invite",
			Error: response.UserFacingMessage(err),
			Token: token,
		})
		return
	}
	next := "/invite?token=" + url.QueryEscape(token)
	h.render.HTMLData(w, "invite.html", invitePageData{
		Title:            "Invite",
		Token:            token,
		Email:            preview.Invite.Email.String(),
		AppName:          preview.Client.Name,
		ClientID:         string(preview.Client.ClientID),
		UserExists:       preview.UserExists,
		LoggedIn:         preview.LoggedIn,
		EmailMatches:     preview.EmailMatches,
		AlreadyHas:       preview.AlreadyHas,
		LoginNext:        url.QueryEscape(next),
		TurnstileSiteKey: h.turnstileKey,
	})
}

func (h *Invite) post(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	token := r.FormValue("token")
	action := r.FormValue("action")

	switch action {
	case "accept":
		if err := h.uc.AcceptExisting(r.Context(), token, response.SessionToken(r)); err != nil {
			h.renderPreviewError(w, r, token, err)
			return
		}
		h.render.HTMLData(w, "invite_done.html", invitePageData{
			Title:   "Invite accepted",
			Success: "Access granted. You can sign in to the app.",
		})
	case "register":
		if err := h.uc.Register(r.Context(), usecase.RegisterViaInviteInput{
			Token:        token,
			Password:     r.FormValue("password"),
			CaptchaToken: r.FormValue("cf-turnstile-response"),
			RemoteIP:     ClientIP(r),
		}); err != nil {
			h.renderPreviewError(w, r, token, err)
			return
		}
		h.render.HTML(w, "verify_sent.html", render.PageData{Title: "Check your email"})
	default:
		http.Error(w, "bad request", http.StatusBadRequest)
	}
}

func (h *Invite) renderPreviewError(w http.ResponseWriter, r *http.Request, token string, err error) {
	preview, previewErr := h.uc.Preview(r.Context(), token, response.SessionToken(r))
	data := invitePageData{
		Title:            "Invite",
		Error:            response.UserFacingMessage(err),
		Token:            token,
		TurnstileSiteKey: h.turnstileKey,
		LoginNext:        url.QueryEscape("/invite?token=" + url.QueryEscape(token)),
	}
	if previewErr == nil {
		data.Email = preview.Invite.Email.String()
		data.AppName = preview.Client.Name
		data.ClientID = string(preview.Client.ClientID)
		data.UserExists = preview.UserExists
		data.LoggedIn = preview.LoggedIn
		data.EmailMatches = preview.EmailMatches
		data.AlreadyHas = preview.AlreadyHas
	}
	h.render.HTMLData(w, "invite.html", data)
}
