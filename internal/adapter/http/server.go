package httpadapter

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/taviani/kde-auth/internal/adapter/http/handler"
	"github.com/taviani/kde-auth/internal/platform/config"
)

type Handlers struct {
	Health      *handler.Health
	Register    *handler.Register
	Login       *handler.Login
	VerifyEmail *handler.VerifyEmail
	Logout      *handler.Logout
	Authorize   *handler.Authorize
	Token       *handler.Token
	UserInfo    *handler.UserInfo
	OIDC        *handler.OIDC
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

	r.Get("/authorize", h.Authorize.ServeHTTP)
	r.Post("/token", h.Token.ServeHTTP)
	r.Get("/userinfo", h.UserInfo.ServeHTTP)

	_ = cfg
	return r
}
