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
	uc     *usecase.AdminUsers
	render *render.Renderer
}

func NewAdmin(uc *usecase.AdminUsers, render *render.Renderer) *Admin {
	return &Admin{uc: uc, render: render}
}

type adminPageData struct {
	Title    string
	Error    string
	Actor    domain.User
	Stats    domain.UserStats
	Result   usecase.AdminUsersResult
	Query    string
	Status   string
	Role     string
	Client   string
	Page     int
	PrevPage int
	NextPage int
}

func (h *Admin) Dashboard(w http.ResponseWriter, r *http.Request) {
	actor, _ := AdminUser(r.Context())
	stats, err := h.uc.Dashboard(r.Context())
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
	result, err := h.uc.List(r.Context(), filter)
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
	if err := h.uc.SetStatus(r.Context(), actor, id, status); err != nil {
		http.Error(w, response.UserFacingMessage(err), http.StatusBadRequest)
		return
	}
	next := r.FormValue("next")
	if next == "" {
		next = "/admin/users"
	}
	http.Redirect(w, r, next, http.StatusSeeOther)
}
