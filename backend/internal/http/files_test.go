package httpapi_test

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yoruware/ddo-case-betul-sakrak/backend/internal/audit"
	"github.com/yoruware/ddo-case-betul-sakrak/backend/internal/auth"
	"github.com/yoruware/ddo-case-betul-sakrak/backend/internal/download"
	httpapi "github.com/yoruware/ddo-case-betul-sakrak/backend/internal/http"
	"github.com/yoruware/ddo-case-betul-sakrak/backend/internal/permissions"
	"github.com/yoruware/ddo-case-betul-sakrak/backend/internal/retention"
	"github.com/yoruware/ddo-case-betul-sakrak/backend/internal/storage"
	"github.com/yoruware/ddo-case-betul-sakrak/backend/internal/testutil"
	"github.com/yoruware/ddo-case-betul-sakrak/backend/internal/upload"
)

type env struct {
	t                                     *testing.T
	srv                                   *httptest.Server
	pool                                  *pgxpool.Pool
	signer                                *download.Signer
	storeDir                              string
	admin, emp, archivist, legal, manager string
	adminID                               string
	empID                                 string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	pool := testutil.NewPool(t)
	dir := t.TempDir()
	store, err := storage.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	tokens := auth.NewTokenService("test-secret-test-secret-test-secret-12", 15*time.Minute, time.Hour)
	signer := download.NewSigner("signing-key-signing-key-signing-key-1", 5*time.Minute)
	lim := upload.DefaultLimits()
	lim.MaxFileBytes = 64 << 10
	lim.ZipMaxTotal = 4 << 20

	h := httpapi.NewRouter(httpapi.Deps{
		Pool: pool, Tokens: tokens, Perms: permissions.New(pool), Audit: audit.New(pool),
		Store: store, Signer: signer, Limits: lim, CORSOrigin: "http://localhost",
		Retention: retention.New(pool, audit.New(pool), store),
	})
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	e := &env{t: t, srv: srv, pool: pool, signer: signer, storeDir: dir}
	mk := func(email, role string) (string, string) {
		var id string
		err := pool.QueryRow(context.Background(),
			`INSERT INTO users (email, password_hash, full_name, role) VALUES ($1,'x',$1,$2) RETURNING id::text`,
			email, role).Scan(&id)
		if err != nil {
			t.Fatal(err)
		}
		tok, err := tokens.Issue(id, role, auth.TypeAccess)
		if err != nil {
			t.Fatal(err)
		}
		return id, tok
	}
	e.adminID, e.admin = mk("admin@test", "admin")
	e.empID, e.emp = mk("emp@test", "employee")
	_, e.archivist = mk("arsiv@test", "archivist")
	_, e.legal = mk("hukuk@test", "legal")
	_, e.manager = mk("mudur@test", "unit_manager")
	return e
}

func (e *env) do(method, path, token string, body io.Reader, ctype string) (*http.Response, []byte) {
	e.t.Helper()
	req, err := http.NewRequest(method, e.srv.URL+path, body)
	if err != nil {
		e.t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, b
}

func decode(b []byte) map[string]any {
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return m
}

func (e *env) js(method, path, token string, v any) (int, map[string]any) {
	e.t.Helper()
	var rd io.Reader
	if v != nil {
		b, _ := json.Marshal(v)
		rd = bytes.NewReader(b)
	}
	resp, body := e.do(method, path, token, rd, "application/json")
	return resp.StatusCode, decode(body)
}

func (e *env) upload(token, folderID, filename string, content []byte) (int, map[string]any) {
	e.t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormFile("file", filename)
	if err != nil {
		e.t.Fatal(err)
	}
	_, _ = fw.Write(content)
	_ = mw.Close()
	resp, body := e.do("POST", "/api/nodes/"+folderID+"/files", token, &buf, mw.FormDataContentType())
	return resp.StatusCode, decode(body)
}

func (e *env) folder(name, parent string) string {
	e.t.Helper()
	body := map[string]any{"kind": "folder", "name": name}
	if parent != "" {
		body["parent_id"] = parent
	}
	code, m := e.js("POST", "/api/nodes", e.admin, body)
	if code != 201 {
		e.t.Fatalf("klasör oluşturulamadı: %d %v", code, m)
	}
	return str(m, "id")
}

func (e *env) count(q string, args ...any) int {
	e.t.Helper()
	var n int
	if err := e.pool.QueryRow(context.Background(), q, args...).Scan(&n); err != nil {
		e.t.Fatal(err)
	}
	return n
}

func str(m map[string]any, k string) string { s, _ := m[k].(string); return s }

func nodeID(m map[string]any) string {
	nm, _ := m["node"].(map[string]any)
	s, _ := nm["id"].(string)
	return s
}

func nodeName(m map[string]any) string {
	nm, _ := m["node"].(map[string]any)
	s, _ := nm["name"].(string)
	return s
}

func errCode(m map[string]any) string {
	em, _ := m["error"].(map[string]any)
	s, _ := em["code"].(string)
	return s
}

func filesUnder(dir, sub string) int {
	n := 0
	_ = filepath.WalkDir(filepath.Join(dir, sub), func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			n++
		}
		return nil
	})
	return n
}

func buildZip(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, data := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write(data)
	}
	_ = zw.Close()
	return buf.Bytes()
}

func TestYuklemeVeIndirme(t *testing.T) {
	e := newEnv(t)
	rootA := e.folder("Hukuk", "")
	rootB := e.folder("Finans", "")
	content := []byte("gizli sozlesme icerigi\n")
	sum := sha256.Sum256(content)
	wantSHA := hex.EncodeToString(sum[:])
	var fileA, fileB string

	t.Run("başarılı yükleme", func(t *testing.T) {
		code, m := e.upload(e.admin, rootA, "sozlesme.txt", content)
		if code != 201 {
			t.Fatalf("201 bekleniyordu, gelen %d: %v", code, m)
		}
		fileA = nodeID(m)
		if str(m, "sha256") != wantSHA {
			t.Fatalf("sha256 uyuşmuyor: %s", str(m, "sha256"))
		}
		if dd, _ := m["deduplicated"].(bool); dd {
			t.Fatal("ilk yükleme tekilleştirilmiş görünmemeli")
		}
	})

	t.Run("aynı içerik tek kopya saklanır", func(t *testing.T) {
		code, m := e.upload(e.admin, rootB, "kopya.txt", content)
		if code != 201 {
			t.Fatalf("201 bekleniyordu, gelen %d: %v", code, m)
		}
		fileB = nodeID(m)
		if dd, _ := m["deduplicated"].(bool); !dd {
			t.Fatal("ikinci yükleme tekilleştirilmiş olmalı")
		}
		if got := filesUnder(e.storeDir, "blobs"); got != 1 {
			t.Fatalf("diskte 1 blob bekleniyordu, gelen %d", got)
		}
		if got := e.count(`SELECT count(*) FROM blobs`); got != 1 {
			t.Fatalf("blobs tablosunda 1 satır bekleniyordu, gelen %d", got)
		}
		if got := e.count(`SELECT count(*) FROM nodes WHERE kind = 'file'`); got != 2 {
			t.Fatalf("2 dosya düğümü bekleniyordu, gelen %d", got)
		}
		if fileA == "" || fileA == fileB {
			t.Fatal("iki ayrı düğüm bekleniyordu")
		}
	})

	t.Run("yetkiler dosya başına ayrıdır", func(t *testing.T) {
		code, _ := e.js("POST", "/api/nodes/"+fileA+"/acl", e.admin, map[string]any{
			"subject_type": "user", "subject_id": e.empID, "permission": "read", "effect": "allow"})
		if code != 200 {
			t.Fatalf("yetki verilemedi: %d", code)
		}
		if code, _ := e.js("POST", "/api/files/"+fileA+"/download-link", e.emp, nil); code != 200 {
			t.Fatalf("yetkili dosya için bağlantı 200 olmalı: %d", code)
		}
		if code, _ := e.js("POST", "/api/files/"+fileB+"/download-link", e.emp, nil); code != 403 {
			t.Fatalf("aynı içerikli diğer dosya 403 olmalı: %d", code)
		}
	})

	t.Run("imzalı bağlantıyla indirme", func(t *testing.T) {
		_, m := e.js("POST", "/api/files/"+fileA+"/download-link", e.emp, nil)
		resp, body := e.do("GET", str(m, "url"), "", nil, "")
		if resp.StatusCode != 200 || !bytes.Equal(body, content) {
			t.Fatalf("indirme başarısız: %d %q", resp.StatusCode, body)
		}
		if resp.Header.Get("X-Content-Type-Options") != "nosniff" {
			t.Fatal("nosniff başlığı eksik")
		}
		if !strings.HasPrefix(resp.Header.Get("Content-Disposition"), "attachment") {
			t.Fatalf("attachment bekleniyordu: %q", resp.Header.Get("Content-Disposition"))
		}
	})

	t.Run("kurcalanmış imza reddedilir", func(t *testing.T) {
		_, m := e.js("POST", "/api/files/"+fileA+"/download-link", e.emp, nil)
		link := str(m, "url")
		i := strings.LastIndex(link, "&sig=")
		base, sig := link[:i+5], link[i+5:]
		bad := "A"
		if sig[0] == 'A' {
			bad = "B"
		}
		if resp, _ := e.do("GET", base+bad+sig[1:], "", nil, ""); resp.StatusCode != 403 {
			t.Fatalf("403 bekleniyordu, gelen %d", resp.StatusCode)
		}
	})

	t.Run("başkası adına imza kullanılamaz", func(t *testing.T) {
		_, m := e.js("POST", "/api/files/"+fileA+"/download-link", e.emp, nil)
		link := strings.Replace(str(m, "url"), "uid="+e.empID, "uid="+e.adminID, 1)
		if resp, _ := e.do("GET", link, "", nil, ""); resp.StatusCode != 403 {
			t.Fatalf("403 bekleniyordu, gelen %d", resp.StatusCode)
		}
	})

	t.Run("süresi dolmuş bağlantı reddedilir", func(t *testing.T) {
		exp := time.Now().Add(-time.Minute).Unix()
		sig := e.signer.SignAt(fileA, e.empID, exp)
		path := fmt.Sprintf("/api/download/%s?uid=%s&exp=%d&sig=%s", fileA, e.empID, exp, sig)
		if resp, _ := e.do("GET", path, "", nil, ""); resp.StatusCode != 410 {
			t.Fatalf("410 bekleniyordu, gelen %d", resp.StatusCode)
		}
	})

	t.Run("yetki geri alınınca verilmiş bağlantı çalışmaz", func(t *testing.T) {
		_, m := e.js("POST", "/api/files/"+fileA+"/download-link", e.emp, nil)
		link := str(m, "url")
		if resp, _ := e.do("GET", link, "", nil, ""); resp.StatusCode != 200 {
			t.Fatalf("iptalden önce 200 bekleniyordu, gelen %d", resp.StatusCode)
		}
		var entryID string
		err := e.pool.QueryRow(context.Background(),
			`SELECT id::text FROM acl_entries WHERE node_id = $1::uuid AND subject_id = $2::uuid AND permission = 'read'`,
			fileA, e.empID).Scan(&entryID)
		if err != nil {
			t.Fatal(err)
		}
		if code, _ := e.js("DELETE", "/api/nodes/"+fileA+"/acl/"+entryID, e.admin, nil); code != 204 {
			t.Fatalf("yetki kaldırılamadı: %d", code)
		}
		if resp, _ := e.do("GET", link, "", nil, ""); resp.StatusCode != 403 {
			t.Fatalf("iptalden sonra 403 bekleniyordu, gelen %d", resp.StatusCode)
		}
		if code, _ := e.js("POST", "/api/files/"+fileA+"/download-link", e.emp, nil); code != 403 {
			t.Fatalf("yeni bağlantı 403 olmalı: %d", code)
		}
	})

	t.Run("yükleme ve indirmeler denetim zincirinde", func(t *testing.T) {
		if got := e.count(`SELECT count(*) FROM audit_log WHERE action = 'file.upload'`); got != 2 {
			t.Fatalf("2 yükleme kaydı bekleniyordu, gelen %d", got)
		}
		if got := e.count(`SELECT count(*) FROM audit_log WHERE action = 'file.download'`); got < 2 {
			t.Fatalf("en az 2 indirme kaydı bekleniyordu, gelen %d", got)
		}
		res, err := audit.New(e.pool).Verify(context.Background())
		if err != nil || !res.Valid {
			t.Fatalf("zincir geçerli olmalı: %+v %v", res, err)
		}
	})
}

func TestGuvenliYuklemeKurallari(t *testing.T) {
	e := newEnv(t)
	root := e.folder("Kök", "")

	t.Run("zararlı dosya karantinaya alınır", func(t *testing.T) {
		code, m := e.upload(e.admin, root, "temiz-gorunen.txt", append([]byte("selam\n"), upload.EICAR()...))
		if code != 422 || errCode(m) != upload.CodeMalware {
			t.Fatalf("422 malware_detected bekleniyordu: %d %v", code, m)
		}
		if got := e.count(`SELECT count(*) FROM nodes WHERE kind = 'file'`); got != 0 {
			t.Fatalf("dosya düğümü oluşmamalı, gelen %d", got)
		}
		if got := e.count(`SELECT count(*) FROM blobs`); got != 0 {
			t.Fatalf("blob oluşmamalı, gelen %d", got)
		}
		if got := e.count(`SELECT count(*) FROM quarantine_items`); got != 1 {
			t.Fatalf("1 karantina kaydı bekleniyordu, gelen %d", got)
		}
		if got := filesUnder(e.storeDir, "quarantine"); got != 1 {
			t.Fatalf("karantina dizininde 1 dosya bekleniyordu, gelen %d", got)
		}
		if got := filesUnder(e.storeDir, "blobs"); got != 0 {
			t.Fatalf("blob dizini boş olmalı, gelen %d", got)
		}
	})

	t.Run("arşiv içindeki zararlı imza karantinaya alınır", func(t *testing.T) {
		z := buildZip(t, map[string][]byte{"gizli.txt": upload.EICAR()})
		code, m := e.upload(e.admin, root, "paket.zip", z)
		if code != 422 || errCode(m) != upload.CodeMalware {
			t.Fatalf("422 malware_detected bekleniyordu: %d %v", code, m)
		}
		if got := e.count(`SELECT count(*) FROM quarantine_items`); got != 2 {
			t.Fatalf("2 karantina kaydı bekleniyordu, gelen %d", got)
		}
	})

	t.Run("exe başlıklı pdf reddedilir", func(t *testing.T) {
		code, m := e.upload(e.admin, root, "fatura.pdf", append([]byte("MZ\x90\x00"), make([]byte, 64)...))
		if code != 415 || errCode(m) != "content_mismatch" {
			t.Fatalf("415 content_mismatch bekleniyordu: %d %v", code, m)
		}
	})

	t.Run("izin verilmeyen uzantı reddedilir", func(t *testing.T) {
		code, m := e.upload(e.admin, root, "betik.exe", []byte("MZ"))
		if code != 415 || errCode(m) != "unsupported_extension" {
			t.Fatalf("415 unsupported_extension bekleniyordu: %d %v", code, m)
		}
	})

	t.Run("boyut sınırı", func(t *testing.T) {
		code, m := e.upload(e.admin, root, "buyuk.txt", bytes.Repeat([]byte("a"), 70<<10))
		if code != 413 || errCode(m) != "file_too_large" {
			t.Fatalf("413 file_too_large bekleniyordu: %d %v", code, m)
		}
	})

	t.Run("yol gezinmesi içeren ad etkisiz", func(t *testing.T) {
		code, m := e.upload(e.admin, root, "../../evil.txt", []byte("zararsiz metin"))
		switch code {
		case 201:
			if nodeName(m) != "evil.txt" {
				t.Fatalf("ad sadeleştirilmiş olmalı, gelen %q", nodeName(m))
			}
		case 400:
		default:
			t.Fatalf("201 veya 400 bekleniyordu: %d %v", code, m)
		}
		outside := filepath.Join(filepath.Dir(e.storeDir), "evil.txt")
		if _, err := os.Stat(outside); err == nil {
			t.Fatal("saklama dizininin dışına dosya yazılmış")
		}
	})

	t.Run("ZIP bombası reddedilir", func(t *testing.T) {
		z := buildZip(t, map[string][]byte{
			"[Content_Types].xml": []byte("<x/>"),
			"sifir.bin":           make([]byte, 8<<20),
		})
		code, m := e.upload(e.admin, root, "bomba.docx", z)
		if code != 422 || errCode(m) != "archive_rejected" {
			t.Fatalf("422 archive_rejected bekleniyordu: %d %v", code, m)
		}
	})

	t.Run("geçerli docx yapısı kabul edilir", func(t *testing.T) {
		z := buildZip(t, map[string][]byte{
			"[Content_Types].xml": []byte("<x/>"),
			"word/document.xml":   []byte("<d/>"),
		})
		if code, m := e.upload(e.admin, root, "belge.docx", z); code != 201 {
			t.Fatalf("201 bekleniyordu: %d %v", code, m)
		}
	})

	t.Run("yazma yetkisi olmayan yükleyemez", func(t *testing.T) {
		if code, _ := e.upload(e.emp, root, "izinsiz.txt", []byte("merhaba")); code != 403 {
			t.Fatalf("403 bekleniyordu, gelen %d", code)
		}
	})
}
