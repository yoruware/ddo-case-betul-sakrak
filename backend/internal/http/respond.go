package httpapi

import (
	"encoding/json"
	"net/http"
)

func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// Tutarlı hata biçimi: {"error":{"code":"...","message":"..."}}
func WriteError(w http.ResponseWriter, status int, code, msg string) {
	WriteJSON(w, status, map[string]any{
		"error": map[string]string{"code": code, "message": msg},
	})
}