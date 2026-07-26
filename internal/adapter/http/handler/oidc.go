package handler

import (
	"net/http"

	"github.com/taviani/kde-auth/internal/adapter/http/render"
	"github.com/taviani/kde-auth/internal/adapter/http/response"
	"github.com/taviani/kde-auth/internal/port"
	"github.com/taviani/kde-auth/internal/usecase"
)

type OIDC struct {
	metadata *usecase.OIDCMetadata
	issuer   port.TokenIssuer
	render   *render.Renderer
}

func NewOIDC(metadata *usecase.OIDCMetadata, issuer port.TokenIssuer, render *render.Renderer) *OIDC {
	return &OIDC{metadata: metadata, issuer: issuer, render: render}
}

func (h *OIDC) Discovery(w http.ResponseWriter, r *http.Request) {
	response.WriteJSON(w, http.StatusOK, h.metadata.Execute())
}

func (h *OIDC) JWKS(w http.ResponseWriter, r *http.Request) {
	doc, err := h.issuer.JWKS(r.Context())
	if err != nil {
		response.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "jwks unavailable"})
		return
	}
	response.WriteJSON(w, http.StatusOK, doc)
}

func (h *OIDC) Root(w http.ResponseWriter, r *http.Request) {
	h.render.HTMLData(w, "home.html", nil)
}
