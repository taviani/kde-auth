package handler

import (
	"errors"
	"net/http"
	"net/url"

	"github.com/taviani/kde-auth/internal/adapter/http/response"
	"github.com/taviani/kde-auth/internal/domain"
	"github.com/taviani/kde-auth/internal/usecase"
)

type Authorize struct {
	uc           *usecase.Authorize
	logout       *usecase.Logout
	cookieSecure bool
}

func NewAuthorize(uc *usecase.Authorize, logout *usecase.Logout, cookieSecure bool) *Authorize {
	return &Authorize{uc: uc, logout: logout, cookieSecure: cookieSecure}
}

func (h *Authorize) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	in := usecase.AuthorizeInput{
		ClientID:            q.Get("client_id"),
		RedirectURI:         q.Get("redirect_uri"),
		ResponseType:        q.Get("response_type"),
		Scope:               q.Get("scope"),
		State:               q.Get("state"),
		SessionToken:        response.SessionToken(r),
		CodeChallenge:       q.Get("code_challenge"),
		CodeChallengeMethod: q.Get("code_challenge_method"),
	}

	result, err := h.uc.Execute(r.Context(), in)
	if err != nil {
		if errors.Is(err, domain.ErrUnauthorized) {
			next := "/authorize?" + q.Encode()
			http.Redirect(w, r, "/login?next="+url.QueryEscape(next), http.StatusSeeOther)
			return
		}
		if errors.Is(err, domain.ErrNoAppAccess) {
			// Drop the session so the user can sign in with an invited account.
			if h.logout != nil {
				_ = h.logout.Execute(r.Context(), response.SessionToken(r))
			}
			response.ClearSessionCookie(w, h.cookieSecure)
			next := "/authorize?" + q.Encode()
			loginURL := "/login?next=" + url.QueryEscape(next) + "&denied=1"
			http.Redirect(w, r, loginURL, http.StatusSeeOther)
			return
		}
		response.WriteError(w, err)
		return
	}
	http.Redirect(w, r, result.RedirectURL, http.StatusFound)
}
