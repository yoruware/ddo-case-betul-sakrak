package httpapi

import (
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"github.com/yoruware/ddo-case-betul-sakrak/backend/internal/audit"
	"github.com/yoruware/ddo-case-betul-sakrak/backend/internal/permissions"
)

// POST /api/files/{id}/approval-requests  {"note":"..."}  (write gerekir)
func (d Deps) createApproval(w http.ResponseWriter, r *http.Request) {
	p, _ := PrincipalFrom(r.Context())
	fileID := r.PathValue("id")
	if !isUUID(fileID) {
		WriteError(w, http.StatusBadRequest, "invalid_request", "Geçersiz kimlik")
		return
	}
	var req struct {
		Note string `json:"note"`
	}
	if r.ContentLength != 0 && !decodeJSON(w, r, &req) {
		return
	}
	note := strings.TrimSpace(req.Note)
	if utf8.RuneCountInString(note) > 500 {
		WriteError(w, http.StatusBadRequest, "invalid_request", "note en fazla 500 karakter olabilir")
		return
	}
	if !d.authorize(w, r, fileID, permissions.Write) {
		return
	}
	ctx := r.Context()
	var isFile bool
	if err := d.Pool.QueryRow(ctx,
		`SELECT kind = 'file' AND destroyed_at IS NULL FROM nodes WHERE id = $1::uuid`, fileID).Scan(&isFile); err != nil {
		internalError(w, "düğüm okunamadı", err)
		return
	}
	if !isFile {
		WriteError(w, http.StatusBadRequest, "invalid_request", "Onay talebi yalnızca dosyalar için açılır")
		return
	}

	tx, err := d.Pool.Begin(ctx)
	if err != nil {
		internalError(w, "transaction başlatılamadı", err)
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var id string
	var created time.Time
	err = tx.QueryRow(ctx, `
INSERT INTO approval_requests (node_id, requested_by, note) VALUES ($1::uuid, $2::uuid, $3)
RETURNING id::text, created_at`, fileID, p.UserID, note).Scan(&id, &created)
	if err != nil {
		if pgCode(err) == "23505" {
			WriteError(w, http.StatusConflict, "conflict", "Bu dosya için bekleyen bir onay talebi zaten var")
			return
		}
		internalError(w, "talep yazılamadı", err)
		return
	}
	err = d.Audit.AppendTx(ctx, tx, audit.Entry{
		ActorID: p.UserID, Action: "approval.requested", TargetType: "approval_request", TargetID: id,
		New: map[string]any{"node_id": fileID, "note": note},
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
		"id": id, "node_id": fileID, "status": "pending", "created_at": created,
	})
}

// GET /api/approval-requests?status=pending|approved|rejected
// Birim yöneticisi ve admin hepsini, diğerleri yalnızca kendi taleplerini görür.
func (d Deps) listApprovals(w http.ResponseWriter, r *http.Request) {
	p, _ := PrincipalFrom(r.Context())
	status := r.URL.Query().Get("status")
	if status == "" {
		status = "pending"
	}
	if status != "pending" && status != "approved" && status != "rejected" {
		WriteError(w, http.StatusBadRequest, "invalid_request", "status pending, approved veya rejected olmalı")
		return
	}
	mine := p.Role != "unit_manager" && p.Role != "admin"
	rows, err := d.Pool.Query(r.Context(), `
SELECT a.id::text, a.node_id::text, n.name, a.requested_by::text, a.note, a.status,
       a.decided_by::text, a.decided_at, a.decision_comment, a.created_at
FROM approval_requests a JOIN nodes n ON n.id = a.node_id
WHERE a.status = $1 AND ($2::boolean = false OR a.requested_by = $3::uuid)
ORDER BY a.created_at, a.id LIMIT 200`, status, mine, p.UserID)
	if err != nil {
		internalError(w, "talepler okunamadı", err)
		return
	}
	defer rows.Close()
	type item struct {
		ID              string     `json:"id"`
		NodeID          string     `json:"node_id"`
		NodeName        string     `json:"node_name"`
		RequestedBy     string     `json:"requested_by"`
		Note            string     `json:"note"`
		Status          string     `json:"status"`
		DecidedBy       *string    `json:"decided_by"`
		DecidedAt       *time.Time `json:"decided_at"`
		DecisionComment string     `json:"decision_comment"`
		CreatedAt       time.Time  `json:"created_at"`
	}
	items := []item{}
	for rows.Next() {
		var it item
		if err := rows.Scan(&it.ID, &it.NodeID, &it.NodeName, &it.RequestedBy, &it.Note, &it.Status,
			&it.DecidedBy, &it.DecidedAt, &it.DecisionComment, &it.CreatedAt); err != nil {
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

// POST /api/approval-requests/{id}/decide  {"decision":"approve|reject","comment":"..."}
// Yalnızca birim yöneticisi ve admin. Talep sahibi kendi talebini karara bağlayamaz.
func (d Deps) decideApproval(w http.ResponseWriter, r *http.Request) {
	p, _ := PrincipalFrom(r.Context())
	id := r.PathValue("id")
	if !isUUID(id) {
		WriteError(w, http.StatusBadRequest, "invalid_request", "Geçersiz kimlik")
		return
	}
	var req struct {
		Decision string `json:"decision"`
		Comment  string `json:"comment"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	status := map[string]string{"approve": "approved", "reject": "rejected"}[req.Decision]
	comment := strings.TrimSpace(req.Comment)
	if status == "" || utf8.RuneCountInString(comment) > 500 {
		WriteError(w, http.StatusBadRequest, "invalid_request", "decision approve veya reject, comment en fazla 500 karakter olmalı")
		return
	}

	ctx := r.Context()
	tx, err := d.Pool.Begin(ctx)
	if err != nil {
		internalError(w, "transaction başlatılamadı", err)
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Karar tek koşullu UPDATE ile verilir: eşzamanlı isteklerde yalnızca biri kazanır.
	var nodeID string
	err = tx.QueryRow(ctx, `
UPDATE approval_requests SET status = $2, decided_by = $3::uuid, decided_at = now(), decision_comment = $4
WHERE id = $1::uuid AND status = 'pending' AND requested_by <> $3::uuid
RETURNING node_id::text`, id, status, p.UserID, comment).Scan(&nodeID)
	if errors.Is(err, pgx.ErrNoRows) {
		var cur, requester string
		e2 := tx.QueryRow(ctx,
			`SELECT status, requested_by::text FROM approval_requests WHERE id = $1::uuid`, id).Scan(&cur, &requester)
		switch {
		case errors.Is(e2, pgx.ErrNoRows):
			WriteError(w, http.StatusNotFound, "not_found", "Talep bulunamadı")
		case e2 != nil:
			internalError(w, "talep okunamadı", e2)
		case cur != "pending":
			WriteError(w, http.StatusConflict, "already_decided", "Bu talep için karar zaten verilmiş")
		default:
			WriteError(w, http.StatusForbidden, "self_approval", "Kendi talebinizi karara bağlayamazsınız")
		}
		return
	}
	if err != nil {
		internalError(w, "karar yazılamadı", err)
		return
	}
	err = d.Audit.AppendTx(ctx, tx, audit.Entry{
		ActorID: p.UserID, Action: "approval." + status, TargetType: "approval_request", TargetID: id,
		New: map[string]any{"node_id": nodeID, "comment": comment},
	})
	if err != nil {
		internalError(w, "denetim kaydı yazılamadı", err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		internalError(w, "commit başarısız", err)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"id": id, "node_id": nodeID, "status": status, "decided_by": p.UserID,
	})
}
