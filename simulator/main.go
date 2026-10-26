package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/argon2"
)

const (
	simPassword = "Sim12345!"
	blobCount   = 16
	ownerEmail  = "sim.owner@sim.kasadoc.local"
	treeLevels  = 10
)

type config struct {
	DBURL, APIURL, StorageDir string
	Seed                      int64
	Users, Files              int
	LiveInterval              time.Duration
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func fatal(msg string, err error) {
	slog.Error(msg, "err", err)
	os.Exit(1)
}

func loadConfig() (config, error) {
	var c config
	var err error
	c.DBURL = os.Getenv("DATABASE_URL")
	if c.DBURL == "" {
		return c, errors.New("DATABASE_URL tanımlı değil")
	}
	c.APIURL = env("API_URL", "http://backend:8080")
	c.StorageDir = env("STORAGE_DIR", "/data/storage")
	if c.Seed, err = strconv.ParseInt(env("SIM_SEED", "42"), 10, 64); err != nil {
		return c, fmt.Errorf("SIM_SEED: %w", err)
	}
	if c.Users, err = strconv.Atoi(env("SIM_USERS", "50")); err != nil || c.Users < 1 || c.Users > 10000 {
		return c, errors.New("SIM_USERS 1-10000 arasında olmalı")
	}
	if c.Files, err = strconv.Atoi(env("SIM_FILES", "100000")); err != nil || c.Files < 1 || c.Files > 1000000 {
		return c, errors.New("SIM_FILES 1-1000000 arasında olmalı")
	}
	if c.LiveInterval, err = time.ParseDuration(env("SIM_LIVE_INTERVAL", "30s")); err != nil {
		return c, fmt.Errorf("SIM_LIVE_INTERVAL: %w", err)
	}
	return c, nil
}

func connect(ctx context.Context, url string) (*pgxpool.Pool, error) {
	var last error
	for i := 0; i < 30; i++ {
		pool, err := pgxpool.New(ctx, url)
		if err == nil {
			if err = pool.Ping(ctx); err == nil {
				return pool, nil
			}
			pool.Close()
		}
		last = err
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	return nil, last
}

// Backend ile aynı biçim (argon2id); tuz tohumdan türetilir, böylece çıktı tekrarlanabilir.
func hashPassword(pw string, seed int64) string {
	s := sha256.Sum256([]byte("kasadoc-sim-salt:" + strconv.FormatInt(seed, 10)))
	salt := s[:16]
	const m, t, p, k = 64 * 1024, 1, 4, 32
	key := argon2.IDKey([]byte(pw), salt, t, m, p, k)
	b := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", m, t, p, b.EncodeToString(salt), b.EncodeToString(key))
}

type blob struct {
	sha  string
	size int
}

// Sahte belge içerikleri, backend'in içerik adresli düzenine (blobs/xx/<sha256>) yazılır.
func writeBlobs(dir string, seed int64) ([]blob, error) {
	out := make([]blob, 0, blobCount)
	for i := 0; i < blobCount; i++ {
		content := []byte(fmt.Sprintf("KasaDoc simülasyon belgesi #%d (tohum %d)\n%s\n",
			i, seed, strings.Repeat("Bu satır sahte belge içeriğidir. ", 20)))
		sum := sha256.Sum256(content)
		sha := hex.EncodeToString(sum[:])
		p := filepath.Join(dir, "blobs", sha[:2], sha)
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			return nil, err
		}
		if _, err := os.Stat(p); err != nil {
			if err := os.WriteFile(p, content, 0o640); err != nil {
				return nil, err
			}
		}
		out = append(out, blob{sha: sha, size: len(content)})
	}
	return out, nil
}

func seed(ctx context.Context, pool *pgxpool.Pool, c config) error {
	if _, err := pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS sim_state (key TEXT PRIMARY KEY, value TEXT NOT NULL)`); err != nil {
		return err
	}
	var prev string
	err := pool.QueryRow(ctx, `SELECT value FROM sim_state WHERE key = 'seeded'`).Scan(&prev)
	if err == nil {
		slog.Info("seed zaten uygulanmış, atlanıyor", "params", prev)
		return nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}

	start := time.Now()
	blobs, err := writeBlobs(c.StorageDir, c.Seed)
	if err != nil {
		return fmt.Errorf("blob dosyaları yazılamadı: %w", err)
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	s := strconv.FormatInt(c.Seed, 10)
	var ownerID, groupID, liveID string
	if err := tx.QueryRow(ctx, `
SELECT md5($1::text || ':owner')::uuid::text, md5($1::text || ':group')::uuid::text, md5($1::text || ':live')::uuid::text`, s).
		Scan(&ownerID, &groupID, &liveID); err != nil {
		return err
	}
	pw := hashPassword(simPassword, c.Seed)

	run := func(name, sql string, args ...any) error {
		t0 := time.Now()
		tag, err := tx.Exec(ctx, sql, args...)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		slog.Info("seed adımı", "adim", name, "satir", tag.RowsAffected(), "sure", time.Since(t0).Round(time.Millisecond).String())
		return nil
	}

	if err := run("sahip kullanıcı", `
INSERT INTO users (id, email, password_hash, full_name, role)
VALUES ($1::uuid, $2, $3, 'Simülasyon Sahibi', 'archivist')`, ownerID, ownerEmail, pw); err != nil {
		return err
	}
	if err := run("kullanıcılar", `
INSERT INTO users (id, email, password_hash, full_name, role)
SELECT md5($1::text || ':user:' || i)::uuid, 'sim' || lpad(i::text, 3, '0') || '@sim.kasadoc.local', $2::text,
       'Sim Kullanıcı ' || i,
       CASE WHEN i % 10 = 0 THEN 'unit_manager' ELSE 'employee' END
FROM generate_series(1, $3::int) i`, s, pw, c.Users); err != nil {
		return err
	}
	if err := run("grup", `INSERT INTO groups (id, name) VALUES ($1::uuid, 'sim-tum-kullanicilar')`, groupID); err != nil {
		return err
	}
	if err := run("grup üyeleri", `
INSERT INTO group_members (group_id, user_id)
SELECT $1::uuid, id FROM users WHERE email ~ '^sim[0-9]+@sim\.kasadoc\.local$'`, groupID); err != nil {
		return err
	}

	if err := run("klasörler seviye 1", `
INSERT INTO nodes (id, parent_id, kind, name, owner_id, ancestor_ids)
SELECT id, NULL, 'folder', 'Birim-' || lpad(r::text, 2, '0'), $2::uuid, ARRAY[id]
FROM (SELECT r, md5($1::text || ':root:' || r)::uuid AS id FROM generate_series(1, 10) r) q`, s, ownerID); err != nil {
		return err
	}
	for lvl := 2; lvl <= treeLevels; lvl++ {
		if err := run(fmt.Sprintf("klasörler seviye %d", lvl), `
INSERT INTO nodes (id, parent_id, kind, name, owner_id, ancestor_ids)
SELECT x.cid, p.id, 'folder', 'k' || c || '-' || substr(p.id::text, 1, 6), $2::uuid, p.ancestor_ids || x.cid
FROM nodes p
CROSS JOIN generate_series(0, 1) c
CROSS JOIN LATERAL (SELECT md5($1::text || p.id::text || ':' || c)::uuid AS cid) x
WHERE p.owner_id = $2::uuid AND p.kind = 'folder' AND cardinality(p.ancestor_ids) = $3::int`,
			s, ownerID, lvl-1); err != nil {
			return err
		}
	}

	if err := run("dosyalar", `
WITH f AS (
  SELECT id, ancestor_ids, row_number() OVER (ORDER BY id) AS rn
  FROM nodes WHERE kind = 'folder' AND owner_id = $2::uuid
), cnt AS (SELECT count(*) AS c FROM f)
INSERT INTO nodes (id, parent_id, kind, name, owner_id, ancestor_ids)
SELECT x.fid, f.id, 'file', 'belge-' || n || '.txt', $2::uuid, f.ancestor_ids || x.fid
FROM generate_series(1, $3::int) n
CROSS JOIN cnt
CROSS JOIN LATERAL (SELECT md5($1::text || ':file:' || n)::uuid AS fid) x
JOIN f ON f.rn = ((n - 1) % cnt.c) + 1`, s, ownerID, c.Files); err != nil {
		return err
	}

	if _, err := tx.Exec(ctx, `CREATE TEMP TABLE sim_blobs (idx int, sha text, size bigint) ON COMMIT DROP`); err != nil {
		return err
	}
	for i, b := range blobs {
		if _, err := tx.Exec(ctx, `INSERT INTO blobs (sha256, size_bytes) VALUES ($1, $2) ON CONFLICT (sha256) DO NOTHING`, b.sha, b.size); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO sim_blobs (idx, sha, size) VALUES ($1, $2, $3)`, i, b.sha, b.size); err != nil {
			return err
		}
	}
	if err := run("sürümler", `
INSERT INTO file_versions (node_id, version_no, sha256, size_bytes, mime_type, original_name, uploaded_by)
SELECT n.id, v, b.sha, b.size, 'text/plain', n.name, $1::uuid
FROM nodes n
CROSS JOIN LATERAL generate_series(1, 1 + get_byte(decode(md5(n.id::text), 'hex'), 0) % 3) v
JOIN sim_blobs b ON b.idx = get_byte(decode(md5(n.id::text || ':' || v), 'hex'), 1) % $2::int
WHERE n.kind = 'file' AND n.owner_id = $1::uuid`, ownerID, blobCount); err != nil {
		return err
	}

	if err := run("kök yetkileri (allow)", `
INSERT INTO acl_entries (node_id, subject_type, subject_id, permission, effect, created_by)
SELECT n.id, 'group', $2::uuid, 'read', 'allow', $1::uuid
FROM nodes n WHERE n.parent_id IS NULL AND n.owner_id = $1::uuid`, ownerID, groupID); err != nil {
		return err
	}
	if err := run("derin yetkiler (deny)", `
INSERT INTO acl_entries (node_id, subject_type, subject_id, permission, effect, created_by)
SELECT n.id, 'group', $2::uuid, 'read', 'deny', $1::uuid
FROM nodes n WHERE n.kind = 'folder' AND n.owner_id = $1::uuid AND cardinality(n.ancestor_ids) = 8
ORDER BY md5(n.id::text) LIMIT 100`, ownerID, groupID); err != nil {
		return err
	}

	// Canlı yüklemelerin gideceği klasör, ağaç ve dosyalar oluştuktan sonra eklenir.
	if err := run("canlı klasör", `
INSERT INTO nodes (id, parent_id, kind, name, owner_id, ancestor_ids)
VALUES ($1::uuid, NULL, 'folder', 'Simulator-Yukleme', $2::uuid, ARRAY[$1::uuid])`, liveID, ownerID); err != nil {
		return err
	}
	if err := run("canlı klasör yetkisi", `
INSERT INTO acl_entries (node_id, subject_type, subject_id, permission, effect, created_by)
SELECT $1::uuid, 'group', $3::uuid, p, 'allow', $2::uuid FROM unnest(ARRAY['read', 'write']) p`,
		liveID, ownerID, groupID); err != nil {
		return err
	}

	params := fmt.Sprintf("seed=%d users=%d files=%d", c.Seed, c.Users, c.Files)
	if _, err := tx.Exec(ctx, `INSERT INTO sim_state (key, value) VALUES ('seeded', $1)`, params); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	slog.Info("seed tamamlandı", "params", params, "sure", time.Since(start).Round(time.Millisecond).String())
	return nil
}

func login(ctx context.Context, cl *http.Client, api, email, pw string) (string, error) {
	body, _ := json.Marshal(map[string]string{"email": email, "password": pw})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, api+"/api/auth/login", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := cl.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return "", fmt.Errorf("giriş başarısız: %d", resp.StatusCode)
	}
	var out struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	return out.AccessToken, nil
}

func upload(ctx context.Context, cl *http.Client, url, token, name string, content []byte) (int, error) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormFile("file", name)
	if err != nil {
		return 0, err
	}
	_, _ = fw.Write(content)
	_ = mw.Close()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, &buf)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	resp, err := cl.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, nil
}

// Her döngüde API üzerinden: normal yükleme, ara sıra zararlı imzalı ve sahte uzantılı denemeler.
func liveCycle(ctx context.Context, cl *http.Client, c config, folder string, n int64) {
	tok, err := login(ctx, cl, c.APIURL, "sim001@sim.kasadoc.local", simPassword)
	if err != nil {
		slog.Error("canlı giriş başarısız", "err", err)
		return
	}
	path := c.APIURL + "/api/nodes/" + folder + "/files"
	do := func(kind, name string, content []byte, want int) {
		code, err := upload(ctx, cl, path, tok, name, content)
		if err != nil {
			slog.Error("canlı yükleme hatası", "tur", kind, "err", err)
			return
		}
		lvl := slog.LevelInfo
		if code != want {
			lvl = slog.LevelWarn
		}
		slog.Log(ctx, lvl, "canlı yükleme", "tur", kind, "ad", name, "durum", code, "beklenen", want)
	}
	do("normal", fmt.Sprintf("canli-%d.txt", n), []byte(fmt.Sprintf("canlı yükleme %d\n", n)), 201)
	if n%3 == 0 {
		do("zararli_imza", fmt.Sprintf("supheli-%d.txt", n), []byte("merhaba\nKASADOC-TEST-MALWARE\n"), 422)
	}
	if n%5 == 0 {
		do("sahte_uzanti", fmt.Sprintf("fatura-%d.pdf", n), append([]byte("MZ\x90\x00"), make([]byte, 64)...), 415)
	}
}

func live(ctx context.Context, c config, folder string) {
	cl := &http.Client{Timeout: 30 * time.Second}
	n := time.Now().Unix() // yeniden başlatmada ad çakışması olmasın
	t := time.NewTicker(c.LiveInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		n++
		liveCycle(ctx, cl, c, folder, n)
	}
}

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
	c, err := loadConfig()
	if err != nil {
		fatal("yapılandırma geçersiz", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := connect(ctx, c.DBURL)
	if err != nil {
		fatal("veritabanına bağlanılamadı", err)
	}
	defer pool.Close()
	if err := seed(ctx, pool, c); err != nil {
		fatal("seed başarısız", err)
	}
	if c.LiveInterval <= 0 {
		slog.Info("canlı üretim kapalı")
		return
	}
	var liveFolder string
	if err := pool.QueryRow(ctx, `SELECT md5($1::text || ':live')::uuid::text`, strconv.FormatInt(c.Seed, 10)).Scan(&liveFolder); err != nil {
		fatal("canlı klasör kimliği alınamadı", err)
	}
	slog.Info("canlı üretim başladı", "aralik", c.LiveInterval.String(), "klasor", liveFolder)
	live(ctx, c, liveFolder)
}