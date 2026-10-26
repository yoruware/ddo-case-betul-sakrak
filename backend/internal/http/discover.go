package httpapi

import (
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/yoruware/ddo-case-betul-sakrak/backend/internal/audit"
	"github.com/yoruware/ddo-case-betul-sakrak/backend/internal/permissions"
)

var (
	tagRe       = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)
	likeEscaper = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
)

func normTag(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// POST /api/nodes/{id}/tags  {"tag":"gizli"}  (write gerekir; var olan etiket 200, yeni 201)
func (d Deps) addTag(w http.ResponseWriter, r *http.Request) {
	p, _ := PrincipalFrom(r.Context())
	nodeID := r.PathValue("id")
	if !isUUID(nodeID) {
		WriteError(w, http.StatusBadRequest, "invalid_request", "Geçersiz kimlik")
		return
	}
	var req struct {
		Tag string `json:"tag"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	tag := normTag(req.Tag)
	if !tagRe.MatchString(tag) {
		WriteError(w, http.StatusBadRequest, "invalid_request", "Etiket 1-32 karakter: küçük harf, rakam, _ ve -")
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

	ct, err := tx.Exec(ctx,
		`INSERT INTO node_tags (node_id, tag, created_by) VALUES ($1::uuid, $2, $3::uuid) ON CONFLICT DO NOTHING`,
		nodeID, tag, p.UserID)
	if err != nil {
		internalError(w, "etiket eklenemedi", err)
		return
	}
	status := http.StatusOK
	if ct.RowsAffected() == 1 {
		status = http.StatusCreated
		err = d.Audit.AppendTx(ctx, tx, audit.Entry{
			ActorID: p.UserID, Action: "tag.added", TargetType: "node", TargetID: nodeID,
			New: map[string]any{"tag": tag},
		})
		if err != nil {
			internalError(w, "denetim kaydı yazılamadı", err)
			return
		}
	}
	if err := tx.Commit(ctx); err != nil {
		internalError(w, "commit başarısız", err)
		return
	}
	WriteJSON(w, status, map[string]string{"node_id": nodeID, "tag": tag})
}

// DELETE /api/nodes/{id}/tags/{tag}  (write gerekir)
func (d Deps) removeTag(w http.ResponseWriter, r *http.Request) {
	p, _ := PrincipalFrom(r.Context())
	nodeID := r.PathValue("id")
	tag := normTag(r.PathValue("tag"))
	if !isUUID(nodeID) || !tagRe.MatchString(tag) {
		WriteError(w, http.StatusBadRequest, "invalid_request", "Geçersiz kimlik veya etiket")
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

	ct, err := tx.Exec(ctx, `DELETE FROM node_tags WHERE node_id = $1::uuid AND tag = $2`, nodeID, tag)
	if err != nil {
		internalError(w, "etiket silinemedi", err)
		return
	}
	if ct.RowsAffected() == 0 {
		WriteError(w, http.StatusNotFound, "not_found", "Etiket bulunamadı")
		return
	}
	err = d.Audit.AppendTx(ctx, tx, audit.Entry{
		ActorID: p.UserID, Action: "tag.removed", TargetType: "node", TargetID: nodeID,
		Old: map[string]any{"tag": tag},
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

// GET /api/nodes/{id}/tags  (read gerekir)
func (d Deps) listTags(w http.ResponseWriter, r *http.Request) {
	nodeID := r.PathValue("id")
	if !isUUID(nodeID) {
		WriteError(w, http.StatusBadRequest, "invalid_request", "Geçersiz kimlik")
		return
	}
	if !d.authorize(w, r, nodeID, permissions.Read) {
		return
	}
	rows, err := d.Pool.Query(r.Context(), `SELECT tag FROM node_tags WHERE node_id = $1::uuid ORDER BY tag`, nodeID)
	if err != nil {
		internalError(w, "etiketler okunamadı", err)
		return
	}
	defer rows.Close()
	tags := []string{}
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			internalError(w, "satır okunamadı", err)
			return
		}
		tags = append(tags, t)
	}
	if err := rows.Err(); err != nil {
		internalError(w, "liste okunamadı", err)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"node_id": nodeID, "tags": tags})
}

// Yetki süzgeci listNodes ile aynıdır (aclMatch): allow var, deny yok.
var searchSQL = `
SELECT n.id::text, n.parent_id::text, n.kind, n.name, n.owner_id::text, n.created_at
FROM nodes n
WHERE n.destroyed_at IS NULL
  AND ($2::uuid IS NULL OR n.id > $2::uuid)
  AND ($4::text = '' OR n.name ILIKE '%' || $4::text || '%' ESCAPE '\')
  AND ($5::text = '' OR n.kind = $5::text)
  AND ($6::text = '' OR EXISTS (SELECT 1 FROM node_tags t WHERE t.node_id = n.id AND t.tag = $6::text))
  AND EXISTS (` + fmt.Sprintf(aclMatch, "'allow'") + `)
  AND NOT EXISTS (` + fmt.Sprintf(aclMatch, "'deny'") + `)
ORDER BY n.id
LIMIT $3`

// GET /api/search?q=&tag=&kind=file|folder&limit=&after=
func (d Deps) searchNodes(w http.ResponseWriter, r *http.Request) {
	p, _ := PrincipalFrom(r.Context())
	q := r.URL.Query()

	text := strings.TrimSpace(q.Get("q"))
	if utf8.RuneCountInString(text) > 100 {
		WriteError(w, http.StatusBadRequest, "invalid_request", "q en fazla 100 karakter olabilir")
		return
	}
	kind := q.Get("kind")
	if kind != "" && kind != "file" && kind != "folder" {
		WriteError(w, http.StatusBadRequest, "invalid_request", "kind file veya folder olmalı")
		return
	}
	tag := normTag(q.Get("tag"))
	if tag != "" && !tagRe.MatchString(tag) {
		WriteError(w, http.StatusBadRequest, "invalid_request", "tag geçersiz")
		return
	}
	var after *string
	if v := q.Get("after"); v != "" {
		if !isUUID(v) {
			WriteError(w, http.StatusBadRequest, "invalid_request", "after geçersiz")
			return
		}
		after = &v
	}
	limit := 50
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 200 {
			WriteError(w, http.StatusBadRequest, "invalid_request", "limit 1-200 arasında olmalı")
			return
		}
		limit = n
	}

	rows, err := d.Pool.Query(r.Context(), searchSQL,
		p.UserID, after, limit+1, likeEscaper.Replace(text), kind, tag)
	if err != nil {
		internalError(w, "arama sorgusu başarısız", err)
		return
	}
	defer rows.Close()

	items := []nodeResp{}
	for rows.Next() {
		var n nodeResp
		if err := rows.Scan(&n.ID, &n.ParentID, &n.Kind, &n.Name, &n.OwnerID, &n.CreatedAt); err != nil {
			internalError(w, "satır okunamadı", err)
			return
		}
		items = append(items, n)
	}
	if err := rows.Err(); err != nil {
		internalError(w, "sonuçlar okunamadı", err)
		return
	}
	var next *string
	if len(items) > limit {
		items = items[:limit]
		last := items[limit-1].ID
		next = &last
	}
	WriteJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": next})
}
