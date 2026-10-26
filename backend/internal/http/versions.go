package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/yoruware/ddo-case-betul-sakrak/backend/internal/audit"
	"github.com/yoruware/ddo-case-betul-sakrak/backend/internal/permissions"
	"github.com/yoruware/ddo-case-betul-sakrak/backend/internal/retention"
)

// Sürüm numarası verilirken aynı dosyaya eşzamanlı yazanlar bu satır kilidiyle sıraya girer.
func lockLiveFile(ctx context.Context, tx pgx.Tx, nodeID string) error {
	var one int
	return tx.QueryRow(ctx,
		`SELECT 1 FROM nodes WHERE id = $1::uuid AND kind = 'file' AND destroyed_at IS NULL FOR UPDATE`,
		nodeID).Scan(&one)
}

// POST /api/files/{id}/versions  (multipart, alan: file; write yetkisi gerekir)
func (d Deps) uploadVersion(w http.ResponseWriter, r *http.Request) {
	p, _ := PrincipalFrom(r.Context())
	nodeID := r.PathValue("id")
	if !isUUID(nodeID) {
		WriteError(w, http.StatusBadRequest, "invalid_request", "Geçersiz kimlik")
		return
	}
	if !d.authorize(w, r, nodeID, permissions.Write) {
		return
	}
	ctx := r.Context()
	var name string
	err := d.Pool.QueryRow(ctx,
		`SELECT name FROM nodes WHERE id = $1::uuid AND kind = 'file' AND destroyed_at IS NULL`, nodeID).Scan(&name)
	if errors.Is(err, pgx.ErrNoRows) {
		WriteError(w, http.StatusNotFound, "not_found", "Dosya bulunamadı")
		return
	}
	if err != nil {
		internalError(w, "dosya okunamadı", err)
		return
	}
	ext := strings.ToLower(name[strings.LastIndexByte(name, '.')+1:])

	rec, cleanup, ok := d.receiveFile(w, r, nodeID, p.UserID, ext)
	if !ok {
		return
	}
	defer cleanup()
	existed := d.Store.Exists(rec.sha)

	tx, err := d.Pool.Begin(ctx)
	if err != nil {
		internalError(w, "transaction başlatılamadı", err)
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock_shared($1)`, retention.LockKey); err != nil {
		internalError(w, "kilit alınamadı", err)
		return
	}
	if err := lockLiveFile(ctx, tx, nodeID); errors.Is(err, pgx.ErrNoRows) {
		WriteError(w, http.StatusNotFound, "not_found", "Dosya bulunamadı")
		return
	} else if err != nil {
		internalError(w, "dosya kilitlenemedi", err)
		return
	}
	if _, err := tx.Exec(ctx, `INSERT INTO blobs (sha256, size_bytes) VALUES ($1, $2) ON CONFLICT (sha256) DO NOTHING`, rec.sha, rec.size); err != nil {
		internalError(w, "blob kaydı yazılamadı", err)
		return
	}
	var no int
	err = tx.QueryRow(ctx, `
INSERT INTO file_versions (node_id, version_no, sha256, size_bytes, mime_type, original_name, uploaded_by)
SELECT $1::uuid, COALESCE(MAX(version_no), 0) + 1, $2::text, $3::bigint, $4::text, $5::text, $6::uuid
FROM file_versions WHERE node_id = $1::uuid
RETURNING version_no`, nodeID, rec.sha, rec.size, rec.mimeType, rec.name, p.UserID).Scan(&no)
	if err != nil {
		internalError(w, "sürüm kaydı yazılamadı", err)
		return
	}
	err = d.Audit.AppendTx(ctx, tx, audit.Entry{
		ActorID: p.UserID, Action: "file.version_added", TargetType: "node", TargetID: nodeID,
		New: map[string]any{
			"version_no": no, "sha256": rec.sha, "size_bytes": rec.size,
			"mime_type": rec.mimeType, "name": rec.name, "deduplicated": existed,
		},
	})
	if err != nil {
		internalError(w, "denetim kaydı yazılamadı", err)
		return
	}
	if _, err := d.Store.Commit(rec.tmpPath, rec.sha); err != nil {
		internalError(w, "içerik saklanamadı", err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		internalError(w, "commit başarısız", err)
		return
	}
	WriteJSON(w, http.StatusCreated, map[string]any{
		"node_id": nodeID, "version_no": no, "sha256": rec.sha, "size_bytes": rec.size,
		"mime_type": rec.mimeType, "deduplicated": existed,
	})
}

// GET /api/files/{id}/versions  (read yetkisi gerekir)
func (d Deps) listVersions(w http.ResponseWriter, r *http.Request) {
	nodeID := r.PathValue("id")
	if !isUUID(nodeID) {
		WriteError(w, http.StatusBadRequest, "invalid_request", "Geçersiz kimlik")
		return
	}
	if !d.authorize(w, r, nodeID, permissions.Read) {
		return
	}
	rows, err := d.Pool.Query(r.Context(), `
SELECT version_no, sha256, size_bytes, mime_type, original_name, uploaded_by::text, created_at
FROM file_versions WHERE node_id = $1::uuid ORDER BY version_no`, nodeID)
	if err != nil {
		internalError(w, "sürümler okunamadı", err)
		return
	}
	defer rows.Close()
	type item struct {
		VersionNo    int       `json:"version_no"`
		SHA256       string    `json:"sha256"`
		SizeBytes    int64     `json:"size_bytes"`
		MimeType     string    `json:"mime_type"`
		OriginalName string    `json:"original_name"`
		UploadedBy   string    `json:"uploaded_by"`
		CreatedAt    time.Time `json:"created_at"`
	}
	items := []item{}
	for rows.Next() {
		var it item
		if err := rows.Scan(&it.VersionNo, &it.SHA256, &it.SizeBytes, &it.MimeType,
			&it.OriginalName, &it.UploadedBy, &it.CreatedAt); err != nil {
			internalError(w, "satır okunamadı", err)
			return
		}
		items = append(items, it)
	}
	if err := rows.Err(); err != nil {
		internalError(w, "liste okunamadı", err)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"node_id": nodeID, "items": items})
}

// POST /api/files/{id}/versions/{no}/restore: eski sürümün içeriğini YENİ sürüm olarak ekler.
func (d Deps) restoreVersion(w http.ResponseWriter, r *http.Request) {
	p, _ := PrincipalFrom(r.Context())
	nodeID := r.PathValue("id")
	no, convErr := strconv.Atoi(r.PathValue("no"))
	if !isUUID(nodeID) || convErr != nil || no < 1 {
		WriteError(w, http.StatusBadRequest, "invalid_request", "Geçersiz kimlik veya sürüm numarası")
		return
	}
	if !d.authorize(w, r, nodeID, permissions.Write) {
		return
	}
	ctx := r.Context()
	tx, err := d.Pool.Begin(ctx)
	if err != nil {
		internalError(w, "transaction başlatılamadı", err)
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock_shared($1)`, retention.LockKey); err != nil {
		internalError(w, "kilit alınamadı", err)
		return
	}
	if err := lockLiveFile(ctx, tx, nodeID); errors.Is(err, pgx.ErrNoRows) {
		WriteError(w, http.StatusNotFound, "not_found", "Dosya bulunamadı")
		return
	} else if err != nil {
		internalError(w, "dosya kilitlenemedi", err)
		return
	}
	var newNo int
	var sha string
	err = tx.QueryRow(ctx, `
INSERT INTO file_versions (node_id, version_no, sha256, size_bytes, mime_type, original_name, uploaded_by)
SELECT node_id,
       (SELECT MAX(version_no) + 1 FROM file_versions WHERE node_id = $1::uuid),
       sha256, size_bytes, mime_type, original_name, $3::uuid
FROM file_versions WHERE node_id = $1::uuid AND version_no = $2::int
RETURNING version_no, sha256`, nodeID, no, p.UserID).Scan(&newNo, &sha)
	if errors.Is(err, pgx.ErrNoRows) {
		WriteError(w, http.StatusNotFound, "not_found", "Sürüm bulunamadı")
		return
	}
	if err != nil {
		internalError(w, "sürüm geri yüklenemedi", err)
		return
	}
	err = d.Audit.AppendTx(ctx, tx, audit.Entry{
		ActorID: p.UserID, Action: "file.version_restored", TargetType: "node", TargetID: nodeID,
		Old: map[string]any{"restored_version": no},
		New: map[string]any{"version_no": newNo, "sha256": sha},
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
		"node_id": nodeID, "version_no": newNo, "restored_from": no, "sha256": sha,
	})
}
