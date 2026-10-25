package httpapi

import (
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/yoruware/ddo-case-betul-sakrak/backend/internal/permissions"
)

// Kök klasör oluşturabilen roller.
var rootCreators = []string{"admin", "unit_manager", "archivist"}

type nodeResp struct {
	ID        string    `json:"id"`
	ParentID  *string   `json:"parent_id"`
	Kind      string    `json:"kind"`
	Name      string    `json:"name"`
	OwnerID   string    `json:"owner_id"`
	CreatedAt time.Time `json:"created_at"`
}

// ancestor_ids yalnızca burada üretilir: üst düğümün listesi + yeni id.
const insertNodeSQL = `
WITH nid AS (SELECT gen_random_uuid() AS id)
INSERT INTO nodes (id, parent_id, kind, name, owner_id, ancestor_ids)
SELECT nid.id, $1::uuid, $2::text, $3::text, $4::uuid,
       array_append(
         COALESCE((SELECT ancestor_ids FROM nodes WHERE id = $1::uuid), '{}'::uuid[]),
         nid.id)
FROM nid
RETURNING id::text, parent_id::text, kind, name, owner_id::text, created_at`

const grantCreatorSQL = `
INSERT INTO acl_entries (node_id, subject_type, subject_id, permission, effect, created_by)
SELECT $1::uuid, 'user', $2::uuid, p, 'allow', $2::uuid
FROM unnest(ARRAY['read','write','delete','share','manage']) AS p`

func validName(n string) bool {
	if n == "" || utf8.RuneCountInString(n) > 255 || n == "." || n == ".." {
		return false
	}
	return !strings.ContainsAny(n, "/\\\x00")
}

func (d Deps) createNode(w http.ResponseWriter, r *http.Request) {
	p, _ := PrincipalFrom(r.Context())
	var req struct {
		ParentID *string `json:"parent_id"`
		Kind     string  `json:"kind"`
		Name     string  `json:"name"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Kind != "folder" {
		WriteError(w, http.StatusBadRequest, "invalid_request", "Şimdilik yalnızca klasör oluşturulabilir")
		return
	}
	if !validName(req.Name) {
		WriteError(w, http.StatusBadRequest, "invalid_request", "Geçersiz ad (1-255 karakter, / \\ . .. kullanılamaz)")
		return
	}

	ctx := r.Context()
	if req.ParentID == nil {
		if !slices.Contains(rootCreators, p.Role) {
			WriteError(w, http.StatusForbidden, "forbidden", "Kök klasör oluşturma yetkiniz yok")
			return
		}
	} else {
		if !isUUID(*req.ParentID) {
			WriteError(w, http.StatusBadRequest, "invalid_request", "parent_id geçersiz")
			return
		}
		if !d.authorize(w, r, *req.ParentID, permissions.Write) {
			return
		}
		var kind string
		if err := d.Pool.QueryRow(ctx, `SELECT kind FROM nodes WHERE id = $1::uuid`, *req.ParentID).Scan(&kind); err != nil {
			internalError(w, "üst düğüm okunamadı", err)
			return
		}
		if kind != "folder" {
			WriteError(w, http.StatusBadRequest, "invalid_request", "Üst düğüm bir klasör olmalı")
			return
		}
	}

	tx, err := d.Pool.Begin(ctx)
	if err != nil {
		internalError(w, "transaction başlatılamadı", err)
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var n nodeResp
	err = tx.QueryRow(ctx, insertNodeSQL, req.ParentID, req.Kind, req.Name, p.UserID).
		Scan(&n.ID, &n.ParentID, &n.Kind, &n.Name, &n.OwnerID, &n.CreatedAt)
	if err != nil {
		if pgCode(err) == "23505" {
			WriteError(w, http.StatusConflict, "conflict", "Bu klasörde aynı adlı bir öğe var")
			return
		}
		internalError(w, "düğüm eklenemedi", err)
		return
	}
	if _, err := tx.Exec(ctx, grantCreatorSQL, n.ID, p.UserID); err != nil {
		internalError(w, "oluşturan yetkisi yazılamadı", err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		internalError(w, "commit başarısız", err)
		return
	}
	WriteJSON(w, http.StatusCreated, n)
}

const aclMatch = `
  SELECT 1 FROM acl_entries a
  WHERE a.node_id = ANY(n.ancestor_ids) AND a.permission = 'read' AND a.effect = %s
    AND ((a.subject_type = 'user' AND a.subject_id = $1::uuid)
      OR (a.subject_type = 'group' AND a.subject_id IN
           (SELECT group_id FROM group_members WHERE user_id = $1::uuid)))`

// Parametreler: $1 kullanıcı, $2 imleç, $3 limit, [$4 üst klasör].
func listQuery(withParent bool) string {
	cond := "n.parent_id IS NULL"
	if withParent {
		cond = "n.parent_id = $4::uuid"
	}
	return `SELECT n.id::text, n.parent_id::text, n.kind, n.name, n.owner_id::text, n.created_at
FROM nodes n
WHERE ` + cond + `
  AND ($2::uuid IS NULL OR n.id > $2::uuid)
  AND EXISTS (` + fmt.Sprintf(aclMatch, "'allow'") + `)
  AND NOT EXISTS (` + fmt.Sprintf(aclMatch, "'deny'") + `)
ORDER BY n.id
LIMIT $3`
}

func (d Deps) listNodes(w http.ResponseWriter, r *http.Request) {
	p, _ := PrincipalFrom(r.Context())
	q := r.URL.Query()

	parent := q.Get("parent_id")
	if parent != "" && !isUUID(parent) {
		WriteError(w, http.StatusBadRequest, "invalid_request", "parent_id geçersiz")
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

	args := []any{p.UserID, after, limit + 1}
	if parent != "" {
		args = append(args, parent)
	}
	rows, err := d.Pool.Query(r.Context(), listQuery(parent != ""), args...)
	if err != nil {
		internalError(w, "liste sorgusu başarısız", err)
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
		internalError(w, "liste okunamadı", err)
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
