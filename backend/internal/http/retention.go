package httpapi

import (
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"github.com/yoruware/ddo-case-betul-sakrak/backend/internal/audit"
	"github.com/yoruware/ddo-case-betul-sakrak/backend/internal/retention"
)

var docTypeRe = regexp.MustCompile(`^[a-z][a-z0-9_]{1,31}$`)

func retentionError(w http.ResponseWriter, err error) bool {
	switch {
	case err == nil:
		return false
	case errors.Is(err, retention.ErrNotFound):
		WriteError(w, http.StatusNotFound, "not_found", "Kayıt bulunamadı")
	case errors.Is(err, retention.ErrNotFile):
		WriteError(w, http.StatusBadRequest, "invalid_request", "Düğüm bir dosya değil veya imha edilmiş")
	case errors.Is(err, retention.ErrUnknownDocType):
		WriteError(w, http.StatusBadRequest, "unknown_doc_type", "Bilinmeyen belge türü")
	case errors.Is(err, retention.ErrAlreadyAssigned):
		WriteError(w, http.StatusConflict, "conflict", "Bu dosyaya saklama kaydı zaten atanmış")
	case errors.Is(err, retention.ErrDestroyed):
		WriteError(w, http.StatusConflict, "conflict", "Düğüm imha edilmiş")
	default:
		internalError(w, "saklama işlemi başarısız", err)
	}
	return true
}

func (d Deps) listDocTypes(w http.ResponseWriter, r *http.Request) {
	rows, err := d.Pool.Query(r.Context(), `SELECT code, name, retention_days FROM document_types ORDER BY code`)
	if err != nil {
		internalError(w, "belge türleri okunamadı", err)
		return
	}
	defer rows.Close()
	type item struct {
		Code          string `json:"code"`
		Name          string `json:"name"`
		RetentionDays int    `json:"retention_days"`
	}
	items := []item{}
	for rows.Next() {
		var it item
		if err := rows.Scan(&it.Code, &it.Name, &it.RetentionDays); err != nil {
			internalError(w, "satır okunamadı", err)
			return
		}
		items = append(items, it)
	}
	if err := rows.Err(); err != nil {
		internalError(w, "liste okunamadı", err)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (d Deps) createDocType(w http.ResponseWriter, r *http.Request) {
	p, _ := PrincipalFrom(r.Context())
	var req struct {
		Code          string `json:"code"`
		Name          string `json:"name"`
		RetentionDays int    `json:"retention_days"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if !docTypeRe.MatchString(req.Code) || utf8.RuneCountInString(req.Name) < 1 ||
		utf8.RuneCountInString(req.Name) > 100 || req.RetentionDays < 0 || req.RetentionDays > 36500 {
		WriteError(w, http.StatusBadRequest, "invalid_request",
			"code (küçük harf, rakam, _), name (1-100) ve retention_days (0-36500) zorunlu")
		return
	}
	ctx := r.Context()
	tx, err := d.Pool.Begin(ctx)
	if err != nil {
		internalError(w, "transaction başlatılamadı", err)
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = tx.Exec(ctx, `INSERT INTO document_types (code, name, retention_days) VALUES ($1, $2, $3)`,
		req.Code, req.Name, req.RetentionDays)
	if err != nil {
		if pgCode(err) == "23505" {
			WriteError(w, http.StatusConflict, "conflict", "Bu kodlu bir belge türü zaten var")
			return
		}
		internalError(w, "belge türü eklenemedi", err)
		return
	}
	err = d.Audit.AppendTx(ctx, tx, audit.Entry{
		ActorID: p.UserID, Action: "doctype.created", TargetType: "document_type", TargetID: req.Code,
		New: map[string]any{"name": req.Name, "retention_days": req.RetentionDays},
	})
	if err != nil {
		internalError(w, "denetim kaydı yazılamadı", err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		internalError(w, "commit başarısız", err)
		return
	}
	WriteJSON(w, http.StatusCreated, map[string]any{
		"code": req.Code, "name": req.Name, "retention_days": req.RetentionDays,
	})
}

// PUT /api/files/{id}/retention
func (d Deps) assignRetention(w http.ResponseWriter, r *http.Request) {
	p, _ := PrincipalFrom(r.Context())
	nodeID := r.PathValue("id")
	if !isUUID(nodeID) {
		WriteError(w, http.StatusBadRequest, "invalid_request", "Geçersiz kimlik")
		return
	}
	var req struct {
		DocType string `json:"doc_type"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if !docTypeRe.MatchString(req.DocType) {
		WriteError(w, http.StatusBadRequest, "invalid_request", "doc_type geçersiz")
		return
	}
	until, err := d.Retention.AssignRetention(r.Context(), p.UserID, nodeID, req.DocType)
	if retentionError(w, err) {
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"node_id": nodeID, "doc_type": req.DocType, "retention_until": until.UTC(),
	})
}

// GET /api/files/{id}/retention
func (d Deps) getRetention(w http.ResponseWriter, r *http.Request) {
	nodeID := r.PathValue("id")
	if !isUUID(nodeID) {
		WriteError(w, http.StatusBadRequest, "invalid_request", "Geçersiz kimlik")
		return
	}
	var docType *string
	var until, destroyed *time.Time
	var held bool
	err := d.Pool.QueryRow(r.Context(), `
SELECT r.doc_type, r.retention_until, n.destroyed_at,
       EXISTS (SELECT 1 FROM legal_holds h WHERE h.released_at IS NULL AND h.node_id = ANY(n.ancestor_ids))
FROM nodes n LEFT JOIN retention_records r ON r.node_id = n.id
WHERE n.id = $1::uuid AND n.kind = 'file'`, nodeID).Scan(&docType, &until, &destroyed, &held)
	if errors.Is(err, pgx.ErrNoRows) {
		WriteError(w, http.StatusNotFound, "not_found", "Dosya bulunamadı")
		return
	}
	if err != nil {
		internalError(w, "saklama bilgisi okunamadı", err)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"node_id": nodeID, "doc_type": docType, "retention_until": until,
		"destroyed_at": destroyed, "legal_hold_active": held,
	})
}

// POST /api/nodes/{id}/legal-holds (yalnızca hukuk/uyum)
func (d Deps) placeHold(w http.ResponseWriter, r *http.Request) {
	p, _ := PrincipalFrom(r.Context())
	nodeID := r.PathValue("id")
	if !isUUID(nodeID) {
		WriteError(w, http.StatusBadRequest, "invalid_request", "Geçersiz kimlik")
		return
	}
	var req struct {
		CaseRef string `json:"case_ref"`
		Reason  string `json:"reason"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	req.CaseRef = strings.TrimSpace(req.CaseRef)
	if n := utf8.RuneCountInString(req.CaseRef); n < 1 || n > 200 || utf8.RuneCountInString(req.Reason) > 1000 {
		WriteError(w, http.StatusBadRequest, "invalid_request", "case_ref 1-200, reason en fazla 1000 karakter olmalı")
		return
	}
	id, err := d.Retention.PlaceHold(r.Context(), p.UserID, nodeID, req.CaseRef, req.Reason)
	if retentionError(w, err) {
		return
	}
	WriteJSON(w, http.StatusCreated, map[string]any{"id": id, "node_id": nodeID, "case_ref": req.CaseRef})
}

// GET /api/nodes/{id}/legal-holds: düğümü ve atalarını kapsayan bekletmeler
func (d Deps) listHolds(w http.ResponseWriter, r *http.Request) {
	nodeID := r.PathValue("id")
	if !isUUID(nodeID) {
		WriteError(w, http.StatusBadRequest, "invalid_request", "Geçersiz kimlik")
		return
	}
	ctx := r.Context()
	var exists bool
	if err := d.Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM nodes WHERE id = $1::uuid)`, nodeID).Scan(&exists); err != nil {
		internalError(w, "düğüm sorgusu başarısız", err)
		return
	}
	if !exists {
		WriteError(w, http.StatusNotFound, "not_found", "Düğüm bulunamadı")
		return
	}
	rows, err := d.Pool.Query(ctx, `
SELECT h.id::text, h.node_id::text, h.case_ref, h.reason, h.placed_by::text, h.placed_at, h.released_at
FROM legal_holds h JOIN nodes n ON n.id = $1::uuid
WHERE h.node_id = ANY(n.ancestor_ids) ORDER BY h.placed_at DESC LIMIT 200`, nodeID)
	if err != nil {
		internalError(w, "bekletme listesi okunamadı", err)
		return
	}
	defer rows.Close()
	type item struct {
		ID         string     `json:"id"`
		NodeID     string     `json:"node_id"`
		CaseRef    string     `json:"case_ref"`
		Reason     string     `json:"reason"`
		PlacedBy   string     `json:"placed_by"`
		PlacedAt   time.Time  `json:"placed_at"`
		ReleasedAt *time.Time `json:"released_at"`
		Status     string     `json:"status"`
	}
	items := []item{}
	for rows.Next() {
		var it item
		if err := rows.Scan(&it.ID, &it.NodeID, &it.CaseRef, &it.Reason, &it.PlacedBy, &it.PlacedAt, &it.ReleasedAt); err != nil {
			internalError(w, "satır okunamadı", err)
			return
		}
		it.Status = "active"
		if it.ReleasedAt != nil {
			it.Status = "released"
		}
		items = append(items, it)
	}
	if err := rows.Err(); err != nil {
		internalError(w, "liste okunamadı", err)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"items": items})
}

// POST /api/legal-holds/{id}/release (yalnızca hukuk/uyum; tekrar çağrı 204 döner)
func (d Deps) releaseHold(w http.ResponseWriter, r *http.Request) {
	p, _ := PrincipalFrom(r.Context())
	id := r.PathValue("id")
	if !isUUID(id) {
		WriteError(w, http.StatusBadRequest, "invalid_request", "Geçersiz kimlik")
		return
	}
	if _, err := d.Retention.ReleaseHold(r.Context(), p.UserID, id); retentionError(w, err) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// POST /api/retention/run?limit=500 (arşiv sorumlusu, sistem yöneticisi)
func (d Deps) runRetention(w http.ResponseWriter, r *http.Request) {
	p, _ := PrincipalFrom(r.Context())
	limit := 500
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 5000 {
			WriteError(w, http.StatusBadRequest, "invalid_request", "limit 1-5000 arasında olmalı")
			return
		}
		limit = n
	}
	res, err := d.Retention.Run(r.Context(), p.UserID, limit)
	if err != nil {
		internalError(w, "imha çalıştırması başarısız", err)
		return
	}
	WriteJSON(w, http.StatusOK, res)
}

func (d Deps) listCertificates(w http.ResponseWriter, r *http.Request) {
	items, err := d.Retention.ListCertificates(r.Context())
	if err != nil {
		internalError(w, "tutanak listesi okunamadı", err)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (d Deps) getCertificate(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !isUUID(id) {
		WriteError(w, http.StatusBadRequest, "invalid_request", "Geçersiz kimlik")
		return
	}
	c, err := d.Retention.GetCertificate(r.Context(), id)
	if retentionError(w, err) {
		return
	}
	WriteJSON(w, http.StatusOK, c)
}
