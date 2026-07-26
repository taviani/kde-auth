package handler

import (
	"context"
	"net/http"
	"net/url"

	"github.com/taviani/kde-auth/internal/adapter/http/response"
	"github.com/taviani/kde-auth/internal/domain"
	"github.com/taviani/kde-auth/internal/usecase"
)

type ctxKey int

const adminUserKey ctxKey = 1

func AdminUser(ctx context.Context) (domain.User, bool) {
	u, ok := ctx.Value(adminUserKey).(domain.User)
	return u, ok
}

func RequireAdmin(resolve *usecase.ResolveSession) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, err := resolve.Execute(r.Context(), response.SessionToken(r))
			if err != nil {
				nextURL := r.URL.RequestURI()
				http.Redirect(w, r, "/login?next="+url.QueryEscape(nextURL), http.StatusSeeOther)
				return
			}
			if !user.IsAdmin() {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			ctx := context.WithValue(r.Context(), adminUserKey, user)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
