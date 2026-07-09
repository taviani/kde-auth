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
	uc *usecase.Authorize
}

func NewAuthorize(uc *usecase.Authorize) *Authorize {
	return &Authorize{uc: uc}
}

func (h *Authorize) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	in := usecase.AuthorizeInput{
		ClientID:     q.Get("client_id"),
		RedirectURI:  q.Get("redirect_uri"),
		ResponseType: q.Get("response_type"),
		Scope:        q.Get("scope"),
		State:        q.Get("state"),
		SessionToken: response.SessionToken(r),
	}

	result, err := h.uc.Execute(r.Context(), in)
	if err != nil {
		if errors.Is(err, domain.ErrUnauthorized) {
			next := "/authorize?" + q.Encode()
			http.Redirect(w, r, "/login?next="+url.QueryEscape(next), http.StatusSeeOther)
			return
		}
		response.WriteError(w, err)
		return
	}
	http.Redirect(w, r, result.RedirectURL, http.StatusFound)
}
