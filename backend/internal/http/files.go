package httpapi

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/yoruware/ddo-case-betul-sakrak/backend/internal/audit"
	"github.com/yoruware/ddo-case-betul-sakrak/backend/internal/download"
	"github.com/yoruware/ddo-case-betul-sakrak/backend/internal/permissions"
	"github.com/yoruware/ddo-case-betul-sakrak/backend/internal/upload"
)

const insertVersionSQL = `
INSERT INTO file_versions (node_id, version_no, sha256, size_bytes, mime_type, original_name, uploaded_by)
VALUES ($1::uuid, 1, $2, $3, $4, $5, $6::uuid)`

func writeReject(w http.ResponseWriter, rej *upload.Reject) {
	WriteError(w, rej.Status, rej.Code, rej.Message)
}

func writeBodyError(w http.ResponseWriter, err error) {
	var mbe *http.MaxBytesError
	if errors.As(err, &mbe) {
		WriteError(w, http.StatusRequestEntityTooLarge, "file_too_large", "İstek boyut sınırını aşıyor")
		return
	}
	WriteError(w, http.StatusBadRequest, "invalid_request", "İstek gövdesi okunamadı")
}

// POST /api/nodes/{id}/files  (multipart/form-data, alan adı: file)
func (d Deps) uploadFile(w http.ResponseWriter, r *http.Request) {
	p, _ := PrincipalFrom(r.Context())
	parentID := r.PathValue("id")
	if !isUUID(parentID) {
		WriteError(w, http.StatusBadRequest, "invalid_request", "Geçersiz klasör kimliği")
		return
	}
	if !d.authorize(w, r, parentID, permissions.Write) {
		return
	}
	ctx := r.Context()

	var parentKind string
	if err := d.Pool.QueryRow(ctx, `SELECT kind FROM nodes WHERE id = $1::uuid`, parentID).Scan(&parentKind); err != nil {
		internalError(w, "üst düğüm okunamadı", err)
		return
	}
	if parentKind != "folder" {
		WriteError(w, http.StatusBadRequest, "invalid_request", "Dosya yalnızca klasöre yüklenebilir")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, d.Limits.MaxFileBytes+(1<<20))
	mr, err := r.MultipartReader()
	if err != nil {
		WriteError(w, http.StatusBadRequest, "invalid_request", "multipart/form-data gerekli")
		return
	}
	var part *multipart.Part
	for {
		part, err = mr.NextPart()
		if errors.Is(err, io.EOF) {
			WriteError(w, http.StatusBadRequest, "invalid_request", "'file' alanı gerekli")
			return
		}
		if err != nil {
			writeBodyError(w, err)
			return
		}
		if part.FormName() == "file" {
			break
		}
	}

	name := part.FileName()
	ext, rej := upload.ValidateName(name)
	if rej != nil {
		writeReject(w, rej)
		return
	}

	tmp, err := d.Store.NewTemp()
	if err != nil {
		internalError(w, "geçici dosya oluşturulamadı", err)
		return
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath) // taşındıysa zaten yok
	}()

	hasher := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, hasher), io.LimitReader(part, d.Limits.MaxFileBytes+1))
	if err != nil {
		writeBodyError(w, err)
		return
	}
	if n > d.Limits.MaxFileBytes {
		WriteError(w, http.StatusRequestEntityTooLarge, "file_too_large",
			fmt.Sprintf("Dosya boyut sınırını aşıyor (en fazla %d bayt)", d.Limits.MaxFileBytes))
		return
	}
	if n == 0 {
		WriteError(w, http.StatusBadRequest, "invalid_request", "Boş dosya yüklenemez")
		return
	}
	sha := hex.EncodeToString(hasher.Sum(nil))

	head := make([]byte, 8192)
	m, _ := tmp.ReadAt(head, 0)
	head = head[:m]

	// 1) Zararlı imza her şeyden önce gelir: karantina.
	sig, _, serr := upload.Scan(io.NewSectionReader(tmp, 0, n))
	if serr != nil {
		internalError(w, "tarama başarısız", serr)
		return
	}
	if sig != "" {
		d.quarantine(w, r, tmp, tmpPath, name, sha, n, parentID, p.UserID, "Dosya zararlı içerik imzası taşıyor: "+sig)
		return
	}

	// 2) Uzantı / magic byte / MIME, 3) arşiv güvenliği.
	mimeType, rej := upload.CheckContent(ext, head)
	if rej == nil && upload.IsArchive(ext) {
		rej = upload.CheckZip(tmp, n, d.Limits, upload.IsOOXML(ext))
	}
	if rej != nil {
		if rej.Code == upload.CodeMalware {
			d.quarantine(w, r, tmp, tmpPath, name, sha, n, parentID, p.UserID, rej.Message)
			return
		}
		writeReject(w, rej)
		return
	}

	_ = tmp.Close()
	existed := d.Store.Exists(sha)

	tx, err := d.Pool.Begin(ctx)
	if err != nil {
		internalError(w, "transaction başlatılamadı", err)
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `INSERT INTO blobs (sha256, size_bytes) VALUES ($1, $2) ON CONFLICT (sha256) DO NOTHING`, sha, n); err != nil {
		internalError(w, "blob kaydı yazılamadı", err)
		return
	}
	var node nodeResp
	err = tx.QueryRow(ctx, insertNodeSQL, parentID, "file", name, p.UserID).
		Scan(&node.ID, &node.ParentID, &node.Kind, &node.Name, &node.OwnerID, &node.CreatedAt)
	if err != nil {
		if pgCode(err) == "23505" {
			WriteError(w, http.StatusConflict, "conflict", "Bu klasörde aynı adlı bir öğe var")
			return
		}
		internalError(w, "düğüm eklenemedi", err)
		return
	}
	if _, err := tx.Exec(ctx, grantCreatorSQL, node.ID, p.UserID); err != nil {
		internalError(w, "oluşturan yetkisi yazılamadı", err)
		return
	}
	if _, err := tx.Exec(ctx, insertVersionSQL, node.ID, sha, n, mimeType, name, p.UserID); err != nil {
		internalError(w, "sürüm kaydı yazılamadı", err)
		return
	}
	err = d.Audit.AppendTx(ctx, tx, audit.Entry{
		ActorID: p.UserID, Action: "file.upload", TargetType: "node", TargetID: node.ID,
		New: map[string]any{
			"sha256": sha, "size_bytes": n, "mime_type": mimeType, "name": name,
			"parent_id": parentID, "deduplicated": existed,
		},
	})
	if err != nil {
		internalError(w, "denetim kaydı yazılamadı", err)
		return
	}
	// Dosya en son taşınır: veritabanı satırı olup içeriği olmayan durum oluşmaz.
	if _, err := d.Store.Commit(tmpPath, sha); err != nil {
		internalError(w, "içerik saklanamadı", err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		internalError(w, "commit başarısız", err)
		return
	}
	WriteJSON(w, http.StatusCreated, map[string]any{
		"node": node, "version_no": 1, "sha256": sha, "size_bytes": n,
		"mime_type": mimeType, "deduplicated": existed,
	})
}

func (d Deps) quarantine(w http.ResponseWriter, r *http.Request, tmp *os.File, tmpPath, name, sha string,
	size int64, parentID, userID, reason string) {
	ctx := r.Context()
	_ = tmp.Close()

	tx, err := d.Pool.Begin(ctx)
	if err != nil {
		internalError(w, "transaction başlatılamadı", err)
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var qid string
	err = tx.QueryRow(ctx, `
INSERT INTO quarantine_items (sha256, size_bytes, original_name, reason, parent_id, uploaded_by)
VALUES ($1, $2, $3, $4, $5::uuid, $6::uuid) RETURNING id::text`,
		sha, size, name, reason, parentID, userID).Scan(&qid)
	if err != nil {
		internalError(w, "karantina kaydı yazılamadı", err)
		return
	}
	err = d.Audit.AppendTx(ctx, tx, audit.Entry{
		ActorID: userID, Action: "upload.quarantined", TargetType: "quarantine", TargetID: qid,
		New: map[string]any{"sha256": sha, "size_bytes": size, "name": name, "reason": reason, "parent_id": parentID},
	})
	if err != nil {
		internalError(w, "denetim kaydı yazılamadı", err)
		return
	}
	if err := d.Store.Quarantine(tmpPath, qid); err != nil {
		internalError(w, "dosya karantinaya taşınamadı", err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		internalError(w, "commit başarısız", err)
		return
	}
	WriteError(w, http.StatusUnprocessableEntity, upload.CodeMalware,
		"Dosya zararlı içerik imzası taşıyor ve karantinaya alındı")
}

// POST /api/files/{id}/download-link: oturum açmış kullanıcıya bağlı, süreli imzalı bağlantı.
func (d Deps) downloadLink(w http.ResponseWriter, r *http.Request) {
	p, _ := PrincipalFrom(r.Context())
	nodeID := r.PathValue("id")
	if !isUUID(nodeID) {
		WriteError(w, http.StatusBadRequest, "invalid_request", "Geçersiz kimlik")
		return
	}
	if !d.authorize(w, r, nodeID, permissions.Read) {
		return
	}
	var has bool
	err := d.Pool.QueryRow(r.Context(),
		`SELECT EXISTS (SELECT 1 FROM file_versions WHERE node_id = $1::uuid)`, nodeID).Scan(&has)
	if err != nil {
		internalError(w, "sürüm sorgusu başarısız", err)
		return
	}
	if !has {
		WriteError(w, http.StatusNotFound, "not_found", "Bu düğümün indirilebilir bir dosyası yok")
		return
	}
	exp, sig := d.Signer.Sign(nodeID, p.UserID, time.Now())
	link := fmt.Sprintf("/api/download/%s?uid=%s&exp=%d&sig=%s", nodeID, p.UserID, exp, url.QueryEscape(sig))
	WriteJSON(w, http.StatusOK, map[string]any{"url": link, "expires_at": time.Unix(exp, 0).UTC()})
}

// GET /api/download/{id}?uid=&exp=&sig=  (Authorization başlığı gerekmez, imza kimliği taşır)
func (d Deps) downloadFile(w http.ResponseWriter, r *http.Request) {
	nodeID := r.PathValue("id")
	q := r.URL.Query()
	uid, sig := q.Get("uid"), q.Get("sig")
	exp, perr := strconv.ParseInt(q.Get("exp"), 10, 64)
	if !isUUID(nodeID) || !isUUID(uid) || perr != nil || sig == "" {
		WriteError(w, http.StatusBadRequest, "invalid_request", "Geçersiz indirme bağlantısı")
		return
	}
	if err := d.Signer.Verify(nodeID, uid, exp, sig, time.Now()); err != nil {
		if errors.Is(err, download.ErrExpired) {
			WriteError(w, http.StatusGone, "link_expired", "Bağlantının süresi dolmuş")
		} else {
			WriteError(w, http.StatusForbidden, "invalid_signature", "Bağlantı imzası geçersiz")
		}
		return
	}
	ctx := r.Context()

	// Yetki indirme anında yeniden denetlenir: geri alınan yetkiyle eski bağlantı çalışmaz.
	ok, err := d.Perms.Check(ctx, uid, nodeID, permissions.Read)
	if errors.Is(err, permissions.ErrNotFound) {
		WriteError(w, http.StatusNotFound, "not_found", "Dosya bulunamadı")
		return
	}
	if err != nil {
		internalError(w, "yetki kontrolü başarısız", err)
		return
	}
	if !ok {
		WriteError(w, http.StatusForbidden, "forbidden", "Bu dosyaya erişim yetkiniz kalmadı")
		return
	}

	var sha, mimeType, name string
	var size int64
	err = d.Pool.QueryRow(ctx, `
SELECT sha256, mime_type, original_name, size_bytes FROM file_versions
WHERE node_id = $1::uuid ORDER BY version_no DESC LIMIT 1`, nodeID).Scan(&sha, &mimeType, &name, &size)
	if errors.Is(err, pgx.ErrNoRows) {
		WriteError(w, http.StatusNotFound, "not_found", "Dosya bulunamadı")
		return
	}
	if err != nil {
		internalError(w, "sürüm okunamadı", err)
		return
	}
	f, err := d.Store.Open(sha)
	if err != nil {
		internalError(w, "içerik açılamadı", err)
		return
	}
	defer f.Close()

	// Denetim kaydı yazılamazsa indirme yapılmaz (fail closed).
	err = d.Audit.Append(ctx, audit.Entry{
		ActorID: uid, Action: "file.download", TargetType: "node", TargetID: nodeID,
		New: map[string]any{"sha256": sha, "size_bytes": size, "name": name},
	})
	if err != nil {
		internalError(w, "denetim kaydı yazılamadı", err)
		return
	}

	cd := mime.FormatMediaType("attachment", map[string]string{"filename": name})
	if cd == "" {
		cd = "attachment"
	}
	h := w.Header()
	h.Set("Content-Type", mimeType)
	h.Set("Content-Disposition", cd)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Security-Policy", "default-src 'none'; sandbox")
	h.Set("Cache-Control", "private, no-store")
	http.ServeContent(w, r, "", time.Time{}, f)
}

// GET /api/quarantine (admin, denetçi)
func (d Deps) listQuarantine(w http.ResponseWriter, r *http.Request) {
	rows, err := d.Pool.Query(r.Context(), `
SELECT id::text, sha256, size_bytes, original_name, reason, parent_id::text, uploaded_by::text, created_at
FROM quarantine_items ORDER BY created_at DESC LIMIT 200`)
	if err != nil {
		internalError(w, "karantina listesi okunamadı", err)
		return
	}
	defer rows.Close()
	type item struct {
		ID           string    `json:"id"`
		SHA256       string    `json:"sha256"`
		SizeBytes    int64     `json:"size_bytes"`
		OriginalName string    `json:"original_name"`
		Reason       string    `json:"reason"`
		ParentID     *string   `json:"parent_id"`
		UploadedBy   string    `json:"uploaded_by"`
		CreatedAt    time.Time `json:"created_at"`
	}
	items := []item{}
	for rows.Next() {
		var it item
		if err := rows.Scan(&it.ID, &it.SHA256, &it.SizeBytes, &it.OriginalName, &it.Reason,
			&it.ParentID, &it.UploadedBy, &it.CreatedAt); err != nil {
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