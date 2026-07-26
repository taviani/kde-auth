package handler

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/taviani/kde-auth/internal/adapter/http/render"
	"github.com/taviani/kde-auth/internal/adapter/http/response"
	"github.com/taviani/kde-auth/internal/domain"
	"github.com/taviani/kde-auth/internal/usecase"
)

type Admin struct {
	users   *usecase.AdminUsers
	clients *usecase.AdminClients
	invites *usecase.AdminInvites
	render  *render.Renderer
}

func NewAdmin(users *usecase.AdminUsers, clients *usecase.AdminClients, invites *usecase.AdminInvites, render *render.Renderer) *Admin {
	return &Admin{users: users, clients: clients, invites: invites, render: render}
}

type adminPageData struct {
	Title       string
	Error       string
	Success     string
	Actor       domain.User
	Stats       domain.UserStats
	Result      usecase.AdminUsersResult
	Clients     []domain.OAuthClient
	Invites     []domain.Invite
	NewSecret   string
	NewClientID string
	AcceptURL   string
	Query       string
	Status      string
	Role        string
	Client      string
	Page        int
	PrevPage    int
	NextPage    int
}

func (h *Admin) Dashboard(w http.ResponseWriter, r *http.Request) {
	actor, _ := AdminUser(r.Context())
	stats, err := h.users.Dashboard(r.Context())
	if err != nil {
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
	h.render.HTMLData(w, "admin_dashboard.html", adminPageData{
		Title: "Admin",
		Actor: actor,
		Stats: stats,
	})
}

func (h *Admin) Users(w http.ResponseWriter, r *http.Request) {
	actor, _ := AdminUser(r.Context())
	q := r.URL.Query()
	page, _ := strconv.Atoi(q.Get("page"))
	if page < 1 {
		page = 1
	}
	const pageSize = 50
	filter := domain.UserListFilter{
		Query:    strings.TrimSpace(q.Get("q")),
		Status:   domain.UserStatus(q.Get("status")),
		Role:     domain.Role(q.Get("role")),
		ClientID: domain.ClientID(q.Get("client")),
		Limit:    pageSize,
		Offset:   (page - 1) * pageSize,
	}
	result, err := h.users.List(r.Context(), filter)
	if err != nil {
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
	h.render.HTMLData(w, "admin_users.html", adminPageData{
		Title:    "Users",
		Actor:    actor,
		Result:   result,
		Stats:    result.Stats,
		Query:    filter.Query,
		Status:   string(filter.Status),
		Role:     string(filter.Role),
		Client:   string(filter.ClientID),
		Page:     page,
		PrevPage: page - 1,
		NextPage: page + 1,
	})
}

func (h *Admin) SetStatus(w http.ResponseWriter, r *http.Request) {
	actor, ok := AdminUser(r.Context())
	if !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	id := domain.UserID(r.FormValue("user_id"))
	status := domain.UserStatus(r.FormValue("status"))
	if err := h.users.SetStatus(r.Context(), actor, id, status); err != nil {
		http.Error(w, response.UserFacingMessage(err), http.StatusBadRequest)
		return
	}
	next := r.FormValue("next")
	if next == "" {
		next = "/admin/users"
	}
	http.Redirect(w, r, next, http.StatusSeeOther)
}

func (h *Admin) Clients(w http.ResponseWriter, r *http.Request) {
	actor, _ := AdminUser(r.Context())
	clients, err := h.clients.List(r.Context())
	if err != nil {
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
	h.render.HTMLData(w, "admin_clients.html", adminPageData{
		Title:   "OAuth clients",
		Actor:   actor,
		Clients: clients,
	})
}

func (h *Admin) CreateClient(w http.ResponseWriter, r *http.Request) {
	actor, ok := AdminUser(r.Context())
	if !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	clients, _ := h.clients.List(r.Context())
	data := adminPageData{
		Title:   "OAuth clients",
		Actor:   actor,
		Clients: clients,
	}
	result, err := h.clients.Create(r.Context(), actor, usecase.CreateClientInput{
		ClientID:    strings.TrimSpace(r.FormValue("client_id")),
		Name:        strings.TrimSpace(r.FormValue("name")),
		RedirectURI: strings.TrimSpace(r.FormValue("redirect_uri")),
		AccessMode:  strings.TrimSpace(r.FormValue("access_mode")),
	})
	if err != nil {
		data.Error = response.UserFacingMessage(err)
		h.render.HTMLData(w, "admin_clients.html", data)
		return
	}
	clients, _ = h.clients.List(r.Context())
	h.render.HTMLData(w, "admin_clients.html", adminPageData{
		Title:       "OAuth clients",
		Actor:       actor,
		Clients:     clients,
		NewClientID: string(result.Client.ClientID),
		NewSecret:   result.ClientSecret,
		Success:     "Client created. Copy the secret now — it will not be shown again.",
	})
}

func (h *Admin) SetAccessMode(w http.ResponseWriter, r *http.Request) {
	actor, ok := AdminUser(r.Context())
	if !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if err := h.clients.SetAccessMode(r.Context(), actor, r.FormValue("client_id"), r.FormValue("access_mode")); err != nil {
		clients, _ := h.clients.List(r.Context())
		h.render.HTMLData(w, "admin_clients.html", adminPageData{
			Title:   "OAuth clients",
			Actor:   actor,
			Clients: clients,
			Error:   response.UserFacingMessage(err),
		})
		return
	}
	http.Redirect(w, r, "/admin/clients", http.StatusSeeOther)
}

func (h *Admin) Invites(w http.ResponseWriter, r *http.Request) {
	actor, _ := AdminUser(r.Context())
	clients, err := h.clients.List(r.Context())
	if err != nil {
		http.Error(w, "error", http.StatusInternalServerError)
		return
	}
	clientID := domain.ClientID(strings.TrimSpace(r.URL.Query().Get("client")))
	var invites []domain.Invite
	if clientID != "" {
		invites, err = h.invites.List(r.Context(), clientID)
		if err != nil {
			http.Error(w, "error", http.StatusInternalServerError)
			return
		}
	}
	h.render.HTMLData(w, "admin_invites.html", adminPageData{
		Title:   "Invites",
		Actor:   actor,
		Clients: clients,
		Invites: invites,
		Client:  string(clientID),
	})
}

func (h *Admin) CreateInvite(w http.ResponseWriter, r *http.Request) {
	actor, ok := AdminUser(r.Context())
	if !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	clientID := strings.TrimSpace(r.FormValue("client_id"))
	clients, _ := h.clients.List(r.Context())
	result, err := h.invites.Create(r.Context(), actor, usecase.CreateInviteInput{
		ClientID: clientID,
		Email:    strings.TrimSpace(r.FormValue("email")),
	})
	data := adminPageData{
		Title:   "Invites",
		Actor:   actor,
		Clients: clients,
		Client:  clientID,
	}
	if clientID != "" {
		data.Invites, _ = h.invites.List(r.Context(), domain.ClientID(clientID))
	}
	if err != nil {
		data.Error = response.UserFacingMessage(err)
		h.render.HTMLData(w, "admin_invites.html", data)
		return
	}
	data.Success = "Invite created and emailed."
	data.AcceptURL = result.AcceptURL
	data.Invites, _ = h.invites.List(r.Context(), domain.ClientID(clientID))
	h.render.HTMLData(w, "admin_invites.html", data)
}

func (h *Admin) RevokeInvite(w http.ResponseWriter, r *http.Request) {
	actor, ok := AdminUser(r.Context())
	if !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if err := h.invites.Revoke(r.Context(), actor, r.FormValue("invite_id")); err != nil {
		http.Error(w, response.UserFacingMessage(err), http.StatusBadRequest)
		return
	}
	client := r.FormValue("client")
	next := "/admin/invites"
	if client != "" {
		next += "?client=" + client
	}
	http.Redirect(w, r, next, http.StatusSeeOther)
}
