package httpapi

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"regexp"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/yoruware/ddo-case-betul-sakrak/backend/internal/permissions"
)

var uuidRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

func isUUID(s string) bool { return uuidRe.MatchString(s) }

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		WriteError(w, http.StatusBadRequest, "invalid_request", "Geçersiz istek gövdesi")
		return false
	}
	return true
}

func internalError(w http.ResponseWriter, msg string, err error) {
	slog.Error(msg, "err", err)
	WriteError(w, http.StatusInternalServerError, "internal", "Beklenmeyen bir hata oluştu")
}

func pgCode(err error) string {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		return pe.Code
	}
	return ""
}

// authorize: izin yoksa yanıtı kendisi yazar ve false döner.
func (d Deps) authorize(w http.ResponseWriter, r *http.Request, nodeID, perm string) bool {
	p, _ := PrincipalFrom(r.Context())
	ok, err := d.Perms.Check(r.Context(), p.UserID, nodeID, perm)
	switch {
	case errors.Is(err, permissions.ErrNotFound):
		WriteError(w, http.StatusNotFound, "not_found", "Düğüm bulunamadı")
		return false
	case err != nil:
		internalError(w, "yetki kontrolü başarısız", err)
		return false
	case !ok:
		WriteError(w, http.StatusForbidden, "forbidden", "Bu işlem için yetkiniz yok")
		return false
	}
	return true
}
