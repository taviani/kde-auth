package handler

import (
	"errors"
	"net/http"

	"github.com/taviani/kde-auth/internal/adapter/http/render"
	"github.com/taviani/kde-auth/internal/adapter/http/response"
	"github.com/taviani/kde-auth/internal/domain"
	"github.com/taviani/kde-auth/internal/usecase"
)

type Register struct {
	uc           *usecase.RegisterUser
	tickets      *usecase.IssueRegisterTicket
	render       *render.Renderer
	turnstileKey string
}

func NewRegister(uc *usecase.RegisterUser, tickets *usecase.IssueRegisterTicket, render *render.Renderer, turnstileKey string) *Register {
	return &Register{uc: uc, tickets: tickets, render: render, turnstileKey: turnstileKey}
}

func (h *Register) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.get(w, r)
	case http.MethodPost:
		h.post(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (h *Register) IssueTicket(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	result, err := h.tickets.Execute(r.Context(), usecase.IssueRegisterTicketInput{
		ClientID:     r.FormValue("client_id"),
		ClientSecret: r.FormValue("client_secret"),
	})
	if err != nil {
		response.WriteError(w, err)
		return
	}
	response.WriteJSON(w, http.StatusOK, map[string]any{
		"ticket":       result.Ticket,
		"expires_in":   result.ExpiresIn,
		"register_url": result.RegisterURL,
	})
}

func (h *Register) get(w http.ResponseWriter, r *http.Request) {
	ticket := r.URL.Query().Get("ticket")
	if _, err := h.uc.PeekTicket(r.Context(), ticket); err != nil {
		http.NotFound(w, r)
		return
	}
	h.render.HTML(w, "register.html", h.pageData("", ticket, ""))
}

func (h *Register) post(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	ticket := r.FormValue("ticket")
	if _, err := h.uc.PeekTicket(r.Context(), ticket); err != nil {
		http.NotFound(w, r)
		return
	}
	email := r.FormValue("email")
	data := h.pageData(email, ticket, "")
	if r.FormValue("password") != r.FormValue("password_confirm") {
		data.Error = "Passwords do not match."
		h.render.HTML(w, "register.html", data)
		return
	}

	err := h.uc.Execute(r.Context(), usecase.RegisterInput{
		Email:        email,
		Password:     r.FormValue("password"),
		CaptchaToken: r.FormValue("cf-turnstile-response"),
		RemoteIP:     ClientIP(r),
		Ticket:       ticket,
	})
	if err != nil {
		if errors.Is(err, domain.ErrInvalidToken) || errors.Is(err, domain.ErrRegistrationClosed) {
			http.NotFound(w, r)
			return
		}
		data.Error = response.UserFacingMessage(err)
		h.render.HTML(w, "register.html", data)
		return
	}
	h.render.HTML(w, "verify_sent.html", render.PageData{
		Title: "Verify email",
		Email: email,
	})
}

func (h *Register) pageData(email, ticket, errMsg string) render.PageData {
	return render.PageData{
		Title:            "Register",
		Email:            email,
		Ticket:           ticket,
		Error:            errMsg,
		TurnstileSiteKey: h.turnstileKey,
	}
}
