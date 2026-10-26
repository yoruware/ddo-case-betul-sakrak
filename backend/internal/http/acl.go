package httpapi

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/yoruware/ddo-case-betul-sakrak/backend/internal/audit"
	"github.com/yoruware/ddo-case-betul-sakrak/backend/internal/permissions"
)

type aclResp struct {
	ID          string    `json:"id"`
	NodeID      string    `json:"node_id"`
	SubjectType string    `json:"subject_type"`
	SubjectID   string    `json:"subject_id"`
	Permission  string    `json:"permission"`
	Effect      string    `json:"effect"`
	CreatedAt   time.Time `json:"created_at"`
}

var subjectExistsSQL = map[string]string{
	"user":  `SELECT EXISTS (SELECT 1 FROM users  WHERE id = $1::uuid)`,
	"group": `SELECT EXISTS (SELECT 1 FROM groups WHERE id = $1::uuid)`,
}

const upsertACLSQL = `
INSERT INTO acl_entries (node_id, subject_type, subject_id, permission, effect, created_by)
VALUES ($1::uuid, $2, $3::uuid, $4, $5, $6::uuid)
ON CONFLICT (node_id, subject_type, subject_id, permission)
DO UPDATE SET effect = EXCLUDED.effect, created_by = EXCLUDED.created_by, created_at = now()
RETURNING id::text, node_id::text, subject_type, subject_id::text, permission, effect, created_at`

// POST /api/nodes/{id}/acl: izin verir veya reddeder (manage gerekir).
func (d Deps) setACL(w http.ResponseWriter, r *http.Request) {
	p, _ := PrincipalFrom(r.Context())
	nodeID := r.PathValue("id")
	if !isUUID(nodeID) {
		WriteError(w, http.StatusBadRequest, "invalid_request", "Geçersiz düğüm kimliği")
		return
	}
	var req struct {
		SubjectType string `json:"subject_type"`
		SubjectID   string `json:"subject_id"`
		Permission  string `json:"permission"`
		Effect      string `json:"effect"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	existsSQL, okType := subjectExistsSQL[req.SubjectType]
	if !okType || !isUUID(req.SubjectID) || !permissions.Valid(req.Permission) ||
		(req.Effect != "allow" && req.Effect != "deny") {
		WriteError(w, http.StatusBadRequest, "invalid_request",
			"subject_type (user|group), subject_id (uuid), permission ve effect (allow|deny) zorunlu")
		return
	}
	if !d.authorize(w, r, nodeID, permissions.Manage) {
		return
	}
	ctx := r.Context()
	var exists bool
	if err := d.Pool.QueryRow(ctx, existsSQL, req.SubjectID).Scan(&exists); err != nil {
		internalError(w, "özne sorgusu başarısız", err)
		return
	}
	if !exists {
		WriteError(w, http.StatusNotFound, "subject_not_found", "Kullanıcı veya grup bulunamadı")
		return
	}

	tx, err := d.Pool.Begin(ctx)
	if err != nil {
		internalError(w, "transaction başlatılamadı", err)
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var oldEffect *string
	err = tx.QueryRow(ctx, `
SELECT effect FROM acl_entries
WHERE node_id=$1::uuid AND subject_type=$2 AND subject_id=$3::uuid AND permission=$4 FOR UPDATE`,
		nodeID, req.SubjectType, req.SubjectID, req.Permission).Scan(&oldEffect)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		internalError(w, "mevcut kayıt okunamadı", err)
		return
	}

	var e aclResp
	err = tx.QueryRow(ctx, upsertACLSQL,
		nodeID, req.SubjectType, req.SubjectID, req.Permission, req.Effect, p.UserID).
		Scan(&e.ID, &e.NodeID, &e.SubjectType, &e.SubjectID, &e.Permission, &e.Effect, &e.CreatedAt)
	if err != nil {
		internalError(w, "yetki kaydı yazılamadı", err)
		return
	}

	var old any
	if oldEffect != nil {
		old = map[string]string{"effect": *oldEffect}
	}
	err = d.Audit.AppendTx(ctx, tx, audit.Entry{
		ActorID: p.UserID, Action: "acl.set", TargetType: "node", TargetID: nodeID,
		Old: old,
		New: map[string]string{
			"subject_type": req.SubjectType, "subject_id": req.SubjectID,
			"permission": req.Permission, "effect": req.Effect,
		},
	})
	if err != nil {
		internalError(w, "denetim kaydı yazılamadı", err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		internalError(w, "commit başarısız", err)
		return
	}
	WriteJSON(w, http.StatusOK, e)
}

func (d Deps) revokeACL(w http.ResponseWriter, r *http.Request) {
	p, _ := PrincipalFrom(r.Context())
	nodeID, entryID := r.PathValue("id"), r.PathValue("entryId")
	if !isUUID(nodeID) || !isUUID(entryID) {
		WriteError(w, http.StatusBadRequest, "invalid_request", "Geçersiz kimlik")
		return
	}
	if !d.authorize(w, r, nodeID, permissions.Manage) {
		return
	}
	ctx := r.Context()
	tx, err := d.Pool.Begin(ctx)
	if err != nil {
		internalError(w, "transaction başlatılamadı", err)
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var subjType, subjID, perm, effect string
	err = tx.QueryRow(ctx, `
DELETE FROM acl_entries WHERE id = $1::uuid AND node_id = $2::uuid
RETURNING subject_type, subject_id::text, permission, effect`, entryID, nodeID).
		Scan(&subjType, &subjID, &perm, &effect)
	if errors.Is(err, pgx.ErrNoRows) {
		WriteError(w, http.StatusNotFound, "not_found", "Yetki kaydı bulunamadı")
		return
	}
	if err != nil {
		internalError(w, "yetki kaydı silinemedi", err)
		return
	}
	err = d.Audit.AppendTx(ctx, tx, audit.Entry{
		ActorID: p.UserID, Action: "acl.revoke", TargetType: "node", TargetID: nodeID,
		Old: map[string]string{"subject_type": subjType, "subject_id": subjID, "permission": perm, "effect": effect},
	})
	if err != nil {
		internalError(w, "denetim kaydı yazılamadı", err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		internalError(w, "commit başarısız", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// GET /api/nodes/{id}/effective-permissions[?user_id=...]
// Başkasının yetkisini yalnızca admin, auditor veya düğümde manage sahibi görebilir.
func (d Deps) effective(w http.ResponseWriter, r *http.Request) {
	p, _ := PrincipalFrom(r.Context())
	nodeID := r.PathValue("id")
	if !isUUID(nodeID) {
		WriteError(w, http.StatusBadRequest, "invalid_request", "Geçersiz düğüm kimliği")
		return
	}
	target := p.UserID
	if v := r.URL.Query().Get("user_id"); v != "" && !strings.EqualFold(v, p.UserID) {
		if !isUUID(v) {
			WriteError(w, http.StatusBadRequest, "invalid_request", "user_id geçersiz")
			return
		}
		target = v
		if p.Role != "admin" && p.Role != "auditor" {
			if !d.authorize(w, r, nodeID, permissions.Manage) {
				return
			}
		}
	}
	set, err := d.Perms.Effective(r.Context(), target, nodeID)
	if err != nil {
		if err == permissions.ErrNotFound {
			WriteError(w, http.StatusNotFound, "not_found", "Düğüm bulunamadı")
			return
		}
		internalError(w, "etkin yetki hesaplanamadı", err)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"node_id": nodeID, "user_id": target, "permissions": set,
	})
}
