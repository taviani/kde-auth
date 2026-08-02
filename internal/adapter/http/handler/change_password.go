package handler

import (
	"encoding/json"
	"net/http"

	"github.com/taviani/kde-auth/internal/adapter/http/response"
	"github.com/taviani/kde-auth/internal/domain"
	"github.com/taviani/kde-auth/internal/port"
	"github.com/taviani/kde-auth/internal/usecase"
)

type ChangePassword struct {
	uc     *usecase.ChangePassword
	issuer port.TokenIssuer
}

func NewChangePassword(uc *usecase.ChangePassword, issuer port.TokenIssuer) *ChangePassword {
	return &ChangePassword{uc: uc, issuer: issuer}
}

func (h *ChangePassword) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	token := bearerToken(r)
	if token == "" {
		response.WriteError(w, domain.ErrUnauthorized)
		return
	}
	claims, err := h.issuer.ParseAccessToken(r.Context(), token)
	if err != nil {
		response.WriteError(w, domain.ErrUnauthorized)
		return
	}

	var body struct {
		CurrentPassword    string `json:"current_password"`
		NewPassword        string `json:"new_password"`
		NewPasswordConfirm string `json:"new_password_confirm"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		response.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json"})
		return
	}

	if err := h.uc.Execute(r.Context(), usecase.ChangePasswordInput{
		UserID:             claims.Subject,
		CurrentPassword:    body.CurrentPassword,
		NewPassword:        body.NewPassword,
		NewPasswordConfirm: body.NewPasswordConfirm,
	}); err != nil {
		response.WriteError(w, err)
		return
	}
	response.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
