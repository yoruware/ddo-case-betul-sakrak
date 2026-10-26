package httpapi

import (
	"net/http"
	"strings"
	"time"
	"unicode/utf8"
)

func (d Deps) createGroup(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" || utf8.RuneCountInString(req.Name) > 100 {
		WriteError(w, http.StatusBadRequest, "invalid_request", "Grup adı 1-100 karakter olmalı")
		return
	}
	var id string
	var created time.Time
	err := d.Pool.QueryRow(r.Context(),
		`INSERT INTO groups (name) VALUES ($1) RETURNING id::text, created_at`, req.Name).Scan(&id, &created)
	if err != nil {
		if pgCode(err) == "23505" {
			WriteError(w, http.StatusConflict, "conflict", "Bu adla bir grup zaten var")
			return
		}
		internalError(w, "grup eklenemedi", err)
		return
	}
	WriteJSON(w, http.StatusCreated, map[string]any{"id": id, "name": req.Name, "created_at": created})
}

func (d Deps) addMember(w http.ResponseWriter, r *http.Request) {
	groupID := r.PathValue("id")
	var req struct {
		UserID string `json:"user_id"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if !isUUID(groupID) || !isUUID(req.UserID) {
		WriteError(w, http.StatusBadRequest, "invalid_request", "Geçersiz kimlik")
		return
	}
	_, err := d.Pool.Exec(r.Context(),
		`INSERT INTO group_members (group_id, user_id) VALUES ($1::uuid, $2::uuid) ON CONFLICT DO NOTHING`,
		groupID, req.UserID)
	if err != nil {
		if pgCode(err) == "23503" {
			WriteError(w, http.StatusNotFound, "not_found", "Grup veya kullanıcı bulunamadı")
			return
		}
		internalError(w, "üye eklenemedi", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (d Deps) removeMember(w http.ResponseWriter, r *http.Request) {
	groupID, userID := r.PathValue("id"), r.PathValue("userId")
	if !isUUID(groupID) || !isUUID(userID) {
		WriteError(w, http.StatusBadRequest, "invalid_request", "Geçersiz kimlik")
		return
	}
	if _, err := d.Pool.Exec(r.Context(),
		`DELETE FROM group_members WHERE group_id = $1::uuid AND user_id = $2::uuid`, groupID, userID); err != nil {
		internalError(w, "üye çıkarılamadı", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
