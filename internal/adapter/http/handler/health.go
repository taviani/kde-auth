package handler

import (
	"net/http"

	"github.com/taviani/kde-auth/internal/adapter/http/response"
	"github.com/taviani/kde-auth/internal/usecase"
)

type Health struct {
	uc *usecase.Health
}

func NewHealth(uc *usecase.Health) *Health {
	return &Health{uc: uc}
}

func (h *Health) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := h.uc.Execute(r.Context()); err != nil {
		response.WriteJSON(w, http.StatusServiceUnavailable, map[string]string{
			"status":  "error",
			"service": "kde-auth",
		})
		return
	}
	response.WriteJSON(w, http.StatusOK, map[string]string{
		"status":  "ok",
		"service": "kde-auth",
	})
}
