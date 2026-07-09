package handler

import (
	"net/http"
	"strings"

	"github.com/taviani/kde-auth/internal/adapter/http/response"
	"github.com/taviani/kde-auth/internal/domain"
	"github.com/taviani/kde-auth/internal/port"
	"github.com/taviani/kde-auth/internal/usecase"
)

type Token struct {
	uc *usecase.ExchangeToken
}

func NewToken(uc *usecase.ExchangeToken) *Token {
	return &Token{uc: uc}
}

func (h *Token) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	result, err := h.uc.Execute(r.Context(), usecase.TokenInput{
		GrantType:    r.FormValue("grant_type"),
		Code:         r.FormValue("code"),
		RedirectURI:  r.FormValue("redirect_uri"),
		ClientID:     r.FormValue("client_id"),
		ClientSecret: r.FormValue("client_secret"),
		RefreshToken: r.FormValue("refresh_token"),
	})
	if err != nil {
		response.WriteError(w, err)
		return
	}
	response.WriteJSON(w, http.StatusOK, map[string]any{
		"access_token":  result.AccessToken,
		"token_type":    result.TokenType,
		"expires_in":    result.ExpiresIn,
		"refresh_token": result.RefreshToken,
		"scope":         result.Scope,
	})
}

type UserInfo struct {
	uc     *usecase.UserInfo
	issuer port.TokenIssuer
}

func NewUserInfo(uc *usecase.UserInfo, issuer port.TokenIssuer) *UserInfo {
	return &UserInfo{uc: uc, issuer: issuer}
}

func (h *UserInfo) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	token := bearerToken(r)
	if token == "" {
		response.WriteError(w, domain.ErrUnauthorized)
		return
	}
	claims, err := h.issuer.ParseAccessToken(r.Context(), token)
	if err != nil {
		response.WriteError(w, err)
		return
	}
	info, err := h.uc.Execute(r.Context(), claims)
	if err != nil {
		response.WriteError(w, err)
		return
	}
	response.WriteJSON(w, http.StatusOK, info)
}

func bearerToken(r *http.Request) string {
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, "Bearer ") {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))
}
