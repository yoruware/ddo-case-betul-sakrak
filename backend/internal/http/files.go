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
	"github.com/yoruware/ddo-case-betul-sakrak/backend/internal/retention"
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

type received struct {
	name, sha, mimeType, tmpPath string
	size                         int64
}

// receiveFile: multipart gövdesindeki "file" alanını geçici dosyaya alır ve doğrular
// (ad, boyut, zararlı imza, magic byte/MIME, arşiv güvenliği). Zararlı içerik karantinaya alınır.
// wantExt doluysa dosya uzantısı onunla aynı olmalıdır. ok=false ise yanıt yazılmıştır.
// Başarıda dönen cleanup fonksiyonu (defer ile) çağrılmalıdır.
func (d Deps) receiveFile(w http.ResponseWriter, r *http.Request, parentID, userID, wantExt string) (*received, func(), bool) {
	r.Body = http.MaxBytesReader(w, r.Body, d.Limits.MaxFileBytes+(1<<20))
	mr, err := r.MultipartReader()
	if err != nil {
		WriteError(w, http.StatusBadRequest, "invalid_request", "multipart/form-data gerekli")
		return nil, nil, false
	}
	var part *multipart.Part
	for {
		part, err = mr.NextPart()
		if errors.Is(err, io.EOF) {
			WriteError(w, http.StatusBadRequest, "invalid_request", "'file' alanı gerekli")
			return nil, nil, false
		}
		if err != nil {
			writeBodyError(w, err)
			return nil, nil, false
		}
		if part.FormName() == "file" {
			break
		}
	}

	name := part.FileName()
	ext, rej := upload.ValidateName(name)
	if rej != nil {
		writeReject(w, rej)
		return nil, nil, false
	}
	if wantExt != "" && ext != wantExt {
		WriteError(w, http.StatusUnsupportedMediaType, "extension_mismatch",
			"Yeni sürümün uzantısı mevcut dosyayla aynı olmalı")
		return nil, nil, false
	}

	tmp, err := d.Store.NewTemp()
	if err != nil {
		internalError(w, "geçici dosya oluşturulamadı", err)
		return nil, nil, false
	}
	tmpPath := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath) // taşındıysa zaten yok
	}

	hasher := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, hasher), io.LimitReader(part, d.Limits.MaxFileBytes+1))
	if err != nil {
		cleanup()
		writeBodyError(w, err)
		return nil, nil, false
	}
	if n > d.Limits.MaxFileBytes {
		cleanup()
		WriteError(w, http.StatusRequestEntityTooLarge, "file_too_large",
			fmt.Sprintf("Dosya boyut sınırını aşıyor (en fazla %d bayt)", d.Limits.MaxFileBytes))
		return nil, nil, false
	}
	if n == 0 {
		cleanup()
		WriteError(w, http.StatusBadRequest, "invalid_request", "Boş dosya yüklenemez")
		return nil, nil, false
	}
	sha := hex.EncodeToString(hasher.Sum(nil))

	head := make([]byte, 8192)
	m, _ := tmp.ReadAt(head, 0)
	head = head[:m]

	// 1) Zararlı imza her şeyden önce gelir: karantina.
	sig, _, serr := upload.Scan(io.NewSectionReader(tmp, 0, n))
	if serr != nil {
		cleanup()
		internalError(w, "tarama başarısız", serr)
		return nil, nil, false
	}
	if sig != "" {
		d.quarantine(w, r, tmp, tmpPath, name, sha, n, parentID, userID, "Dosya zararlı içerik imzası taşıyor: "+sig)
		cleanup()
		return nil, nil, false
	}

	// 2) Uzantı / magic byte / MIME, 3) arşiv güvenliği.
	mimeType, rej := upload.CheckContent(ext, head)
	if rej == nil && upload.IsArchive(ext) {
		rej = upload.CheckZip(tmp, n, d.Limits, upload.IsOOXML(ext))
	}
	if rej != nil {
		if rej.Code == upload.CodeMalware {
			d.quarantine(w, r, tmp, tmpPath, name, sha, n, parentID, userID, rej.Message)
		} else {
			writeReject(w, rej)
		}
		cleanup()
		return nil, nil, false
	}
	_ = tmp.Close()
	return &received{name: name, sha: sha, mimeType: mimeType, tmpPath: tmpPath, size: n},
		func() { _ = os.Remove(tmpPath) }, true
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

	rec, cleanup, ok := d.receiveFile(w, r, parentID, p.UserID, "")
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

	// Yükleme paylaşımlı, imha özel kilit alır: blob silinirken aynı içerik yeniden bağlanamaz.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock_shared($1)`, retention.LockKey); err != nil {
		internalError(w, "kilit alınamadı", err)
		return
	}
	if _, err := tx.Exec(ctx, `INSERT INTO blobs (sha256, size_bytes) VALUES ($1, $2) ON CONFLICT (sha256) DO NOTHING`, rec.sha, rec.size); err != nil {
		internalError(w, "blob kaydı yazılamadı", err)
		return
	}
	var node nodeResp
	err = tx.QueryRow(ctx, insertNodeSQL, parentID, "file", rec.name, p.UserID).
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
	if _, err := tx.Exec(ctx, insertVersionSQL, node.ID, rec.sha, rec.size, rec.mimeType, rec.name, p.UserID); err != nil {
		internalError(w, "sürüm kaydı yazılamadı", err)
		return
	}
	err = d.Audit.AppendTx(ctx, tx, audit.Entry{
		ActorID: p.UserID, Action: "file.upload", TargetType: "node", TargetID: node.ID,
		New: map[string]any{
			"sha256": rec.sha, "size_bytes": rec.size, "mime_type": rec.mimeType, "name": rec.name,
			"parent_id": parentID, "deduplicated": existed,
		},
	})
	if err != nil {
		internalError(w, "denetim kaydı yazılamadı", err)
		return
	}
	// Dosya en son taşınır: veritabanı satırı olup içeriği olmayan durum oluşmaz.
	if _, err := d.Store.Commit(rec.tmpPath, rec.sha); err != nil {
		internalError(w, "içerik saklanamadı", err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		internalError(w, "commit başarısız", err)
		return
	}
	WriteJSON(w, http.StatusCreated, map[string]any{
		"node": node, "version_no": 1, "sha256": rec.sha, "size_bytes": rec.size,
		"mime_type": rec.mimeType, "deduplicated": existed,
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

// GET /api/download/{id}?uid=&exp=&sig=[&version=N]  (Authorization başlığı gerekmez, imza kimliği taşır)
func (d Deps) downloadFile(w http.ResponseWriter, r *http.Request) {
	nodeID := r.PathValue("id")
	q := r.URL.Query()
	uid, sig := q.Get("uid"), q.Get("sig")
	exp, perr := strconv.ParseInt(q.Get("exp"), 10, 64)
	if !isUUID(nodeID) || !isUUID(uid) || perr != nil || sig == "" {
		WriteError(w, http.StatusBadRequest, "invalid_request", "Geçersiz indirme bağlantısı")
		return
	}
	version := 0 // 0 = son sürüm
	if v := q.Get("version"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			WriteError(w, http.StatusBadRequest, "invalid_request", "version geçersiz")
			return
		}
		version = n
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
	var versionNo int
	err = d.Pool.QueryRow(ctx, `
SELECT sha256, mime_type, original_name, size_bytes, version_no FROM file_versions
WHERE node_id = $1::uuid AND ($2::int = 0 OR version_no = $2::int)
ORDER BY version_no DESC LIMIT 1`, nodeID, version).Scan(&sha, &mimeType, &name, &size, &versionNo)
	if errors.Is(err, pgx.ErrNoRows) {
		WriteError(w, http.StatusNotFound, "not_found", "Dosya veya sürüm bulunamadı")
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
		New: map[string]any{"sha256": sha, "size_bytes": size, "name": name, "version_no": versionNo},
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
