package httpadapter

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/taviani/kde-auth/internal/adapter/http/handler"
	"github.com/taviani/kde-auth/internal/platform/config"
)

type Handlers struct {
	Health         *handler.Health
	Register       *handler.Register
	Login          *handler.Login
	VerifyEmail    *handler.VerifyEmail
	Logout         *handler.Logout
	ForgotPassword *handler.ForgotPassword
	ResetPassword  *handler.ResetPassword
	Authorize      *handler.Authorize
	Token          *handler.Token
	UserInfo       *handler.UserInfo
	OIDC           *handler.OIDC
	Admin          *handler.Admin
	RequireAdmin   func(http.Handler) http.Handler
}

func NewRouter(cfg config.Config, h Handlers) http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	r.Get("/health", h.Health.ServeHTTP)
	r.Get("/", h.OIDC.Root)

	r.Get("/.well-known/openid-configuration", h.OIDC.Discovery)
	r.Get("/jwks", h.OIDC.JWKS)

	r.Get("/register", h.Register.ServeHTTP)
	r.Post("/register", h.Register.ServeHTTP)
	r.Get("/login", h.Login.ServeHTTP)
	r.Post("/login", h.Login.ServeHTTP)
	r.Get("/verify-email", h.VerifyEmail.ServeHTTP)
	r.Post("/logout", h.Logout.ServeHTTP)
	r.Get("/forgot-password", h.ForgotPassword.ServeHTTP)
	r.Post("/forgot-password", h.ForgotPassword.ServeHTTP)
	r.Get("/reset-password", h.ResetPassword.ServeHTTP)
	r.Post("/reset-password", h.ResetPassword.ServeHTTP)

	r.Get("/authorize", h.Authorize.ServeHTTP)
	r.Post("/token", h.Token.ServeHTTP)
	r.Get("/userinfo", h.UserInfo.ServeHTTP)

	if h.Admin != nil && h.RequireAdmin != nil {
		r.Route("/admin", func(ar chi.Router) {
			ar.Use(h.RequireAdmin)
			ar.Get("/", h.Admin.Dashboard)
			ar.Get("/users", h.Admin.Users)
			ar.Post("/users/status", h.Admin.SetStatus)
			ar.Get("/clients", h.Admin.Clients)
			ar.Post("/clients", h.Admin.CreateClient)
		})
	}

	_ = cfg
	return r
}
