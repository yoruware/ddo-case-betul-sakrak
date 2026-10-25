package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"github.com/yoruware/ddo-case-betul-sakrak/backend/internal/audit"
	"github.com/yoruware/ddo-case-betul-sakrak/backend/internal/auth"
	"github.com/yoruware/ddo-case-betul-sakrak/backend/internal/permissions"
	"github.com/yoruware/ddo-case-betul-sakrak/backend/internal/ratelimit"
)

const (
	shareMinTTLSeconds = 60
	shareMaxTTLSeconds = 30 * 24 * 3600
	shareMaxDownloads  = 10000
)

type ShareGuards struct {
	IP          *ratelimit.Limiter // istemci adresi başına genel istek sınırı
	FailPerIP   *ratelimit.Limiter // bağlantı + adres başına hatalı parola
	FailPerLink *ratelimit.Limiter // bağlantı başına toplam hatalı parola (dağıtık saldırı)
}

func NewShareGuards() *ShareGuards {
	return &ShareGuards{
		IP:          ratelimit.New(120, time.Minute),
		FailPerIP:   ratelimit.New(5, 15*time.Minute),
		FailPerLink: ratelimit.New(30, 15*time.Minute),
	}
}

type shareLink struct {
	ID, NodeID, TokenHash, CreatedBy string
	PasswordHash                     *string
	ExpiresAt                        time.Time
	MaxDownloads                     *int
	DownloadCount                    int
	RevokedAt                        *time.Time
}

func hashToken(t string) string {
	s := sha256.Sum256([]byte(t))
	return hex.EncodeToString(s[:])
}

func newShareToken() (token, hash string, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return "", "", err
	}
	token = base64.RawURLEncoding.EncodeToString(b)
	return token, hashToken(token), nil
}

func validTokenShape(t string) bool {
	if len(t) != 43 {
		return false
	}
	for i := 0; i < len(t); i++ {
		c := t[i]
		ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_'
		if !ok {
			return false
		}
	}
	return true
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func setRetryAfter(w http.ResponseWriter, d time.Duration) {
	secs := int(d.Seconds()) + 1
	if secs < 1 {
		secs = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(secs))
}

// auditShare: oturumsuz (anonim) erişimleri de zincire yazar. Ham token asla yazılmaz.
func (d Deps) auditShare(r *http.Request, action, linkID, ip string, info map[string]any) error {
	if info == nil {
		info = map[string]any{}
	}
	info["ip"] = ip
	actor, target := "anonymous", "unknown"
	if linkID != "" {
		actor, target = "share_link:"+linkID, linkID
	}
	err := d.Audit.Append(context.WithoutCancel(r.Context()), audit.Entry{
		ActorID: actor, Action: action, TargetType: "share_link", TargetID: target, New: info,
	})
	if err != nil {
		slog.Error("paylaşım denetim kaydı yazılamadı", "err", err, "action", action)
	}
	return err
}

func (d Deps) loadShareLink(ctx context.Context, hash string) (*shareLink, error) {
	var l shareLink
	err := d.Pool.QueryRow(ctx, `
SELECT id::text, node_id::text, token_hash, password_hash, expires_at, max_downloads,
       download_count, revoked_at, created_by::text
FROM share_links WHERE token_hash = $1`, hash).
		Scan(&l.ID, &l.NodeID, &l.TokenHash, &l.PasswordHash, &l.ExpiresAt, &l.MaxDownloads,
			&l.DownloadCount, &l.RevokedAt, &l.CreatedBy)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &l, nil
}

// POST /api/nodes/{id}/share-links  (share yetkisi gerekir)
func (d Deps) createShareLink(w http.ResponseWriter, r *http.Request) {
	p, _ := PrincipalFrom(r.Context())
	nodeID := r.PathValue("id")
	if !isUUID(nodeID) {
		WriteError(w, http.StatusBadRequest, "invalid_request", "Geçersiz düğüm kimliği")
		return
	}
	var req struct {
		ExpiresInSeconds int64   `json:"expires_in_seconds"`
		Password         *string `json:"password"`
		MaxDownloads     *int    `json:"max_downloads"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	// Taşmayı önlemek için süre, Duration'a çevrilmeden önce saniye olarak denetlenir.
	if req.ExpiresInSeconds < shareMinTTLSeconds || req.ExpiresInSeconds > shareMaxTTLSeconds {
		WriteError(w, http.StatusBadRequest, "invalid_request", "expires_in_seconds 60 ile 2592000 (30 gün) arasında olmalı")
		return
	}
	if req.MaxDownloads != nil && (*req.MaxDownloads < 1 || *req.MaxDownloads > shareMaxDownloads) {
		WriteError(w, http.StatusBadRequest, "invalid_request", "max_downloads 1 ile 10000 arasında olmalı")
		return
	}
	if req.Password != nil {
		if n := utf8.RuneCountInString(*req.Password); n < 8 || n > 128 {
			WriteError(w, http.StatusBadRequest, "invalid_request", "Parola 8-128 karakter olmalı")
			return
		}
	}
	if !d.authorize(w, r, nodeID, permissions.Share) {
		return
	}
	ctx := r.Context()
	var isFile bool
	if err := d.Pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM file_versions WHERE node_id = $1::uuid)`, nodeID).Scan(&isFile); err != nil {
		internalError(w, "dosya sorgusu başarısız", err)
		return
	}
	if !isFile {
		WriteError(w, http.StatusBadRequest, "invalid_request", "Yalnızca dosyalar için bağlantı oluşturulabilir")
		return
	}

	token, hash, err := newShareToken()
	if err != nil {
		internalError(w, "token üretilemedi", err)
		return
	}
	var pwHash *string
	if req.Password != nil {
		h, err := auth.HashPassword(*req.Password)
		if err != nil {
			internalError(w, "parola özeti üretilemedi", err)
			return
		}
		pwHash = &h
	}
	expires := time.Now().Add(time.Duration(req.ExpiresInSeconds) * time.Second)

	tx, err := d.Pool.Begin(ctx)
	if err != nil {
		internalError(w, "transaction başlatılamadı", err)
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var id string
	err = tx.QueryRow(ctx, `
INSERT INTO share_links (node_id, token_hash, password_hash, expires_at, max_downloads, created_by)
VALUES ($1::uuid, $2, $3, $4, $5, $6::uuid) RETURNING id::text`,
		nodeID, hash, pwHash, expires, req.MaxDownloads, p.UserID).Scan(&id)
	if err != nil {
		internalError(w, "bağlantı kaydı yazılamadı", err)
		return
	}
	err = d.Audit.AppendTx(ctx, tx, audit.Entry{
		ActorID: p.UserID, Action: "share.created", TargetType: "share_link", TargetID: id,
		New: map[string]any{
			"node_id": nodeID, "expires_at": expires.UTC(),
			"max_downloads": req.MaxDownloads, "password_protected": pwHash != nil,
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
	w.Header().Set("Cache-Control", "no-store")
	WriteJSON(w, http.StatusCreated, map[string]any{
		"id": id, "token": token,
		"url":                "/api/s/" + token,
		"download_url":       "/api/s/" + token + "/download",
		"expires_at":         expires.UTC(),
		"max_downloads":      req.MaxDownloads,
		"password_protected": pwHash != nil,
	})
}

// GET /api/nodes/{id}/share-links  (share yetkisi gerekir; token ve hash dönmez)
func (d Deps) listShareLinks(w http.ResponseWriter, r *http.Request) {
	nodeID := r.PathValue("id")
	if !isUUID(nodeID) {
		WriteError(w, http.StatusBadRequest, "invalid_request", "Geçersiz düğüm kimliği")
		return
	}
	if !d.authorize(w, r, nodeID, permissions.Share) {
		return
	}
	rows, err := d.Pool.Query(r.Context(), `
SELECT id::text, expires_at, max_downloads, download_count, password_hash IS NOT NULL,
       revoked_at, created_by::text, created_at
FROM share_links WHERE node_id = $1::uuid ORDER BY created_at DESC LIMIT 200`, nodeID)
	if err != nil {
		internalError(w, "bağlantı listesi okunamadı", err)
		return
	}
	defer rows.Close()

	type item struct {
		ID                string     `json:"id"`
		Status            string     `json:"status"`
		ExpiresAt         time.Time  `json:"expires_at"`
		MaxDownloads      *int       `json:"max_downloads"`
		DownloadCount     int        `json:"download_count"`
		PasswordProtected bool       `json:"password_protected"`
		RevokedAt         *time.Time `json:"revoked_at"`
		CreatedBy         string     `json:"created_by"`
		CreatedAt         time.Time  `json:"created_at"`
	}
	now := time.Now()
	items := []item{}
	for rows.Next() {
		var it item
		if err := rows.Scan(&it.ID, &it.ExpiresAt, &it.MaxDownloads, &it.DownloadCount,
			&it.PasswordProtected, &it.RevokedAt, &it.CreatedBy, &it.CreatedAt); err != nil {
			internalError(w, "satır okunamadı", err)
			return
		}
		switch {
		case it.RevokedAt != nil:
			it.Status = "revoked"
		case !now.Before(it.ExpiresAt):
			it.Status = "expired"
		case it.MaxDownloads != nil && it.DownloadCount >= *it.MaxDownloads:
			it.Status = "exhausted"
		default:
			it.Status = "active"
		}
		items = append(items, it)
	}
	if err := rows.Err(); err != nil {
		internalError(w, "liste okunamadı", err)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"items": items})
}

// DELETE /api/share-links/{id}  (düğümde share yetkisi gerekir; tekrar iptal 204 döner)
func (d Deps) revokeShareLink(w http.ResponseWriter, r *http.Request) {
	p, _ := PrincipalFrom(r.Context())
	linkID := r.PathValue("id")
	if !isUUID(linkID) {
		WriteError(w, http.StatusBadRequest, "invalid_request", "Geçersiz kimlik")
		return
	}
	ctx := r.Context()
	var nodeID string
	err := d.Pool.QueryRow(ctx, `SELECT node_id::text FROM share_links WHERE id = $1::uuid`, linkID).Scan(&nodeID)
	if errors.Is(err, pgx.ErrNoRows) {
		WriteError(w, http.StatusNotFound, "not_found", "Bağlantı bulunamadı")
		return
	}
	if err != nil {
		internalError(w, "bağlantı okunamadı", err)
		return
	}
	if !d.authorize(w, r, nodeID, permissions.Share) {
		return
	}

	tx, err := d.Pool.Begin(ctx)
	if err != nil {
		internalError(w, "transaction başlatılamadı", err)
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var revoked string
	err = tx.QueryRow(ctx,
		`UPDATE share_links SET revoked_at = now() WHERE id = $1::uuid AND revoked_at IS NULL RETURNING id::text`,
		linkID).Scan(&revoked)
	switch {
	case err == nil:
		aerr := d.Audit.AppendTx(ctx, tx, audit.Entry{
			ActorID: p.UserID, Action: "share.revoked", TargetType: "share_link", TargetID: linkID,
			Old: map[string]any{"node_id": nodeID},
		})
		if aerr != nil {
			internalError(w, "denetim kaydı yazılamadı", aerr)
			return
		}
		if cerr := tx.Commit(ctx); cerr != nil {
			internalError(w, "commit başarısız", cerr)
			return
		}
	case errors.Is(err, pgx.ErrNoRows):
		// zaten iptal edilmiş
	default:
		internalError(w, "bağlantı iptal edilemedi", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// resolveShare: genel sınır, token biçimi, arama, durum ve oluşturan yetkisi kontrolleri.
// Hata durumunda yanıtı kendisi yazar.
func (d Deps) resolveShare(w http.ResponseWriter, r *http.Request) (*shareLink, string, bool) {
	ip := clientIP(r)
	if n, retry := d.Share.IP.Hit(ip); n > d.Share.IP.Max() {
		setRetryAfter(w, retry)
		WriteError(w, http.StatusTooManyRequests, "rate_limited", "Çok fazla istek, lütfen biraz bekleyin")
		return nil, ip, false
	}

	token := r.PathValue("token")
	fp := "malformed"
	if validTokenShape(token) {
		fp = hashToken(token)[:8]
	}
	notFound := func(reason string) {
		_ = d.auditShare(r, "share.denied", "", ip, map[string]any{"reason": reason, "token_fp": fp})
		WriteError(w, http.StatusNotFound, "not_found", "Bağlantı bulunamadı")
	}
	if fp == "malformed" {
		notFound("malformed_token")
		return nil, ip, false
	}

	hash := hashToken(token)
	link, err := d.loadShareLink(r.Context(), hash)
	if err != nil {
		internalError(w, "bağlantı sorgusu başarısız", err)
		return nil, ip, false
	}
	if link == nil || subtle.ConstantTimeCompare([]byte(link.TokenHash), []byte(hash)) != 1 {
		notFound("unknown_token")
		return nil, ip, false
	}

	gone := func(reason string) {
		_ = d.auditShare(r, "share.denied", link.ID, ip, map[string]any{"reason": reason})
		WriteError(w, http.StatusGone, "link_unavailable", "Bağlantı geçersiz, süresi dolmuş veya iptal edilmiş")
	}
	if link.RevokedAt != nil {
		gone("revoked")
		return nil, ip, false
	}
	if !time.Now().Before(link.ExpiresAt) {
		gone("expired")
		return nil, ip, false
	}
	if link.MaxDownloads != nil && link.DownloadCount >= *link.MaxDownloads {
		gone("exhausted")
		return nil, ip, false
	}
	// Bağlantı, oluşturanın yetkisini aşamaz: oluşturan okuma yetkisini kaybettiyse bağlantı da kapanır.
	ok, err := d.Perms.Check(r.Context(), link.CreatedBy, link.NodeID, permissions.Read)
	if err != nil && !errors.Is(err, permissions.ErrNotFound) {
		internalError(w, "yetki kontrolü başarısız", err)
		return nil, ip, false
	}
	if err != nil || !ok {
		gone("creator_lost_access")
		return nil, ip, false
	}
	return link, ip, true
}

// GET /api/s/{token}: kimlik gerekmez, dosya bilgisi döner (indirme sayacını artırmaz).
func (d Deps) shareInfo(w http.ResponseWriter, r *http.Request) {
	link, ip, ok := d.resolveShare(w, r)
	if !ok {
		return
	}
	var name, mimeType string
	var size int64
	err := d.Pool.QueryRow(r.Context(), `
SELECT original_name, mime_type, size_bytes FROM file_versions
WHERE node_id = $1::uuid ORDER BY version_no DESC LIMIT 1`, link.NodeID).Scan(&name, &mimeType, &size)
	if err != nil {
		internalError(w, "dosya bilgisi okunamadı", err)
		return
	}
	_ = d.auditShare(r, "share.view", link.ID, ip, nil)

	var remaining *int
	if link.MaxDownloads != nil {
		v := *link.MaxDownloads - link.DownloadCount
		remaining = &v
	}
	w.Header().Set("Cache-Control", "no-store")
	WriteJSON(w, http.StatusOK, map[string]any{
		"name": name, "size_bytes": size, "mime_type": mimeType,
		"requires_password": link.PasswordHash != nil,
		"expires_at":        link.ExpiresAt.UTC(),
		"remaining_downloads": remaining,
	})
}

func serveBlob(w http.ResponseWriter, f io.Reader, mimeType, name string, size int64) {
	cd := mime.FormatMediaType("attachment", map[string]string{"filename": name})
	if cd == "" {
		cd = "attachment"
	}
	h := w.Header()
	h.Set("Content-Type", mimeType)
	h.Set("Content-Disposition", cd)
	h.Set("Content-Length", strconv.FormatInt(size, 10))
	h.Set("Accept-Ranges", "none") // aralıklı istekler sayacı bölmesin
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Security-Policy", "default-src 'none'; sandbox")
	h.Set("Cache-Control", "private, no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, f)
}

// GET|POST /api/s/{token}/download: parolasız bağlantılar GET ile, parolalılar POST {"password":"..."} ile.
func (d Deps) shareDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Yalnızca GET veya POST")
		return
	}
	link, ip, ok := d.resolveShare(w, r)
	if !ok {
		return
	}
	ctx := r.Context()

	if link.PasswordHash != nil {
		if r.Method != http.MethodPost {
			WriteError(w, http.StatusUnauthorized, "password_required",
				"Bu bağlantı parola gerektiriyor; parolayı POST gövdesinde gönderin")
			return
		}
		var req struct {
			Password string `json:"password"`
		}
		if !decodeJSON(w, r, &req) {
			return
		}
		ipKey := link.ID + "|" + ip
		nIP, retryIP := d.Share.FailPerIP.Count(ipKey)
		nLink, retryLink := d.Share.FailPerLink.Count(link.ID)
		if nIP >= d.Share.FailPerIP.Max() || nLink >= d.Share.FailPerLink.Max() {
			retry := retryIP
			if retryLink > retry {
				retry = retryLink
			}
			setRetryAfter(w, retry)
			_ = d.auditShare(r, "share.denied", link.ID, ip, map[string]any{"reason": "locked"})
			WriteError(w, http.StatusTooManyRequests, "too_many_attempts", "Çok fazla hatalı deneme, daha sonra tekrar deneyin")
			return
		}
		if !auth.VerifyPassword(req.Password, *link.PasswordHash) {
			d.Share.FailPerIP.Hit(ipKey)
			d.Share.FailPerLink.Hit(link.ID)
			_ = d.auditShare(r, "share.denied", link.ID, ip, map[string]any{"reason": "bad_password"})
			WriteError(w, http.StatusUnauthorized, "invalid_password", "Parola hatalı")
			return
		}
		d.Share.FailPerIP.Reset(ipKey)
	}

	var sha, mimeType, name string
	var size int64
	err := d.Pool.QueryRow(ctx, `
SELECT sha256, mime_type, original_name, size_bytes FROM file_versions
WHERE node_id = $1::uuid ORDER BY version_no DESC LIMIT 1`, link.NodeID).Scan(&sha, &mimeType, &name, &size)
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

	tx, err := d.Pool.Begin(ctx)
	if err != nil {
		internalError(w, "transaction başlatılamadı", err)
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Sınır tek atomik koşullu UPDATE ile uygulanır: eşzamanlı isteklerde aşılamaz.
	var count int
	err = tx.QueryRow(ctx, `
UPDATE share_links SET download_count = download_count + 1
WHERE id = $1::uuid AND revoked_at IS NULL AND expires_at > now()
  AND (max_downloads IS NULL OR download_count < max_downloads)
RETURNING download_count`, link.ID).Scan(&count)
	if errors.Is(err, pgx.ErrNoRows) {
		_ = tx.Rollback(ctx)
		_ = d.auditShare(r, "share.denied", link.ID, ip, map[string]any{"reason": "exhausted_or_expired"})
		WriteError(w, http.StatusGone, "link_unavailable", "Bağlantı geçersiz, süresi dolmuş veya iptal edilmiş")
		return
	}
	if err != nil {
		internalError(w, "indirme sayacı güncellenemedi", err)
		return
	}
	// Denetim kaydı yazılamazsa indirme yapılmaz (fail closed).
	err = d.Audit.AppendTx(ctx, tx, audit.Entry{
		ActorID: "share_link:" + link.ID, Action: "share.download", TargetType: "share_link", TargetID: link.ID,
		New: map[string]any{
			"node_id": link.NodeID, "sha256": sha, "size_bytes": size, "name": name,
			"ip": ip, "download_count": count,
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
	serveBlob(w, f, mimeType, name, size)
}