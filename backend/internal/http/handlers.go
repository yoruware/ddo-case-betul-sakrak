package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/yoruware/ddo-case-betul-sakrak/backend/internal/auth"
)

type loginReq struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type tokenResp struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	Role         string `json:"role"`
}

func (d Deps) issuePair(w http.ResponseWriter, userID, role string) {
	at, err1 := d.Tokens.Issue(userID, role, auth.TypeAccess)
	rt, err2 := d.Tokens.Issue(userID, role, auth.TypeRefresh)
	if err1 != nil || err2 != nil {
		WriteError(w, http.StatusInternalServerError, "internal", "Token üretilemedi")
		return
	}
	WriteJSON(w, http.StatusOK, tokenResp{AccessToken: at, RefreshToken: rt, TokenType: "Bearer", Role: role})
}

func (d Deps) health(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := d.Pool.Ping(ctx); err != nil {
		slog.Error("health: veritabanı erişilemiyor", "err", err)
		WriteJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "unhealthy", "database": "down"})
		return
	}
	WriteJSON(w, http.StatusOK, map[string]string{"status": "ok", "database": "up"})
}

func (d Deps) login(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req loginReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, http.StatusBadRequest, "invalid_request", "Geçersiz istek gövdesi")
		return
	}
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))
	if req.Email == "" || req.Password == "" {
		WriteError(w, http.StatusBadRequest, "invalid_request", "E-posta ve parola zorunlu")
		return
	}

	var id, hash, role string
	err := d.Pool.QueryRow(r.Context(),
		`SELECT id::text, password_hash, role FROM users WHERE email = $1`, req.Email).
		Scan(&id, &hash, &role)
	if errors.Is(err, pgx.ErrNoRows) {
		auth.VerifyPassword(req.Password, auth.DummyHash)
		WriteError(w, http.StatusUnauthorized, "invalid_credentials", "E-posta veya parola hatalı")
		return
	}
	if err != nil {
		slog.Error("login: sorgu hatası", "err", err)
		WriteError(w, http.StatusInternalServerError, "internal", "Beklenmeyen bir hata oluştu")
		return
	}
	if !auth.VerifyPassword(req.Password, hash) {
		WriteError(w, http.StatusUnauthorized, "invalid_credentials", "E-posta veya parola hatalı")
		return
	}
	d.issuePair(w, id, role)
}

func (d Deps) refresh(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.RefreshToken == "" {
		WriteError(w, http.StatusBadRequest, "invalid_request", "refresh_token zorunlu")
		return
	}
	claims, err := d.Tokens.Parse(req.RefreshToken, auth.TypeRefresh)
	if err != nil {
		WriteError(w, http.StatusUnauthorized, "unauthorized", "Geçersiz veya süresi dolmuş token")
		return
	}
	// Rol değişmiş olabilir: güncel rolü veritabanından al.
	var role string
	err = d.Pool.QueryRow(r.Context(), `SELECT role FROM users WHERE id = $1::uuid`, claims.Subject).Scan(&role)
	if err != nil {
		WriteError(w, http.StatusUnauthorized, "unauthorized", "Kullanıcı bulunamadı")
		return
	}
	d.issuePair(w, claims.Subject, role)
}

func (d Deps) me(w http.ResponseWriter, r *http.Request) {
	p, _ := PrincipalFrom(r.Context())
	var email, name string
	err := d.Pool.QueryRow(r.Context(),
		`SELECT email, full_name FROM users WHERE id = $1::uuid`, p.UserID).Scan(&email, &name)
	if err != nil {
		WriteError(w, http.StatusNotFound, "not_found", "Kullanıcı bulunamadı")
		return
	}
	WriteJSON(w, http.StatusOK, map[string]string{
		"id": p.UserID, "email": email, "full_name": name, "role": p.Role,
	})
}

func (d Deps) adminPing(w http.ResponseWriter, r *http.Request) {
	WriteJSON(w, http.StatusOK, map[string]string{"message": "pong"})
}