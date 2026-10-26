package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const demoPassword = "Demo1234!"

var accounts = []struct{ key, email, role string }{
	{"calisan", "calisan@kasadoc.local", "employee"},
	{"yonetici", "yonetici@kasadoc.local", "unit_manager"},
	{"arsiv", "arsiv@kasadoc.local", "archivist"},
	{"hukuk", "hukuk@kasadoc.local", "legal"},
	{"denetci", "denetci@kasadoc.local", "auditor"},
	{"admin", "admin@kasadoc.local", "admin"},
}

var order = []struct{ id, title string }{
	{"HEALTH", "Saglik ucu (GET /health)"},
	{"AUTH", "Kimlik dogrulama (giris, yanlis parola, yenileme)"},
	{"RBAC", "Yetki ihlali senaryolari (401/403)"},
	{"F-1", "Klasor ve dosya yonetimi"},
	{"F-2", "Dosya surumleme ve eski surume donus"},
	{"F-3", "Etiket, arama ve filtreleme"},
	{"F-4", "Paylasim: kisi, grup ve sureli baglanti"},
	{"F-5", "Saklama politikasi, hukuki bekletme ve imha"},
	{"F-6", "Onay is akisi"},
	{"F-7", "Erisim kayitlari ve denetim raporlari"},
	{"T-1", "Hiyerarsik yetki modeli"},
	{"T-2", "Guvenli yukleme ve icerik adresli saklama"},
	{"T-3", "Sureli paylasim baglantilari"},
	{"T-4", "Saklama, hukuki bekletme ve kanitlanabilir imha"},
}

type result struct {
	id, name, detail string
	ok               bool
}

type runner struct {
	api, storage, run string
	cl                *http.Client
	db                *pgxpool.Pool
	ctx               context.Context
	results           []result
	tok, refresh      map[string]string
	userID            map[string]string
	baseline          int64
	docType           string
}

type response struct {
	status int
	body   []byte
	header http.Header
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func (r *runner) check(id, name string, ok bool, format string, args ...any) {
	d := ""
	if !ok {
		d = fmt.Sprintf(format, args...)
	}
	r.results = append(r.results, result{id: id, name: name, ok: ok, detail: d})
}

func (r *runner) safe(id string, fn func()) {
	defer func() {
		if rec := recover(); rec != nil {
			r.check(id, "beklenmeyen hata (panic)", false, "%v", rec)
		}
	}()
	fn()
}

// ---------------------------------------------------------------- yardimcilar

func decode(b []byte) map[string]any {
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return m
}
func str(m map[string]any, k string) string { s, _ := m[k].(string); return s }
func num(m map[string]any, k string) int    { f, _ := m[k].(float64); return int(f) }
func sub(m map[string]any, k string) map[string]any {
	s, _ := m[k].(map[string]any)
	return s
}
func list(m map[string]any, k string) []any { s, _ := m[k].([]any); return s }
func errCode(m map[string]any) string       { return str(sub(m, "error"), "code") }

func itemNames(m map[string]any) []string {
	out := []string{}
	for _, it := range list(m, "items") {
		mm, _ := it.(map[string]any)
		out = append(out, str(mm, "name"))
	}
	return out
}

func hasName(names []string, n string) bool {
	for _, x := range names {
		if x == n {
			return true
		}
	}
	return false
}

func shaOf(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func validTok(t string) bool {
	if len(t) != 43 {
		return false
	}
	for _, c := range t {
		ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_'
		if !ok {
			return false
		}
	}
	return true
}

func pct(d []time.Duration, p float64) time.Duration {
	if len(d) == 0 {
		return 0
	}
	s := append([]time.Duration(nil), d...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	return s[int(float64(len(s)-1)*p)]
}

func makeZip(files map[string][]byte) []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, data := range files {
		w, _ := zw.Create(name)
		_, _ = w.Write(data)
	}
	_ = zw.Close()
	return buf.Bytes()
}

func (r *runner) do(method, path, token, ctype string, body io.Reader) response {
	req, err := http.NewRequest(method, r.api+path, body)
	if err != nil {
		return response{body: []byte(err.Error())}
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	resp, err := r.cl.Do(req)
	if err != nil {
		return response{body: []byte(err.Error())}
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return response{status: resp.StatusCode, body: b, header: resp.Header}
}

func (r *runner) js(method, path, token string, v any) (int, map[string]any) {
	var rd io.Reader
	if v != nil {
		b, _ := json.Marshal(v)
		rd = bytes.NewReader(b)
	}
	x := r.do(method, path, token, "application/json", rd)
	return x.status, decode(x.body)
}

func (r *runner) code(method, path, token string) int {
	s, _ := r.js(method, path, token, nil)
	return s
}

func (r *runner) upload(token, path, name string, content []byte) (int, map[string]any) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, _ := mw.CreateFormFile("file", name)
	_, _ = fw.Write(content)
	_ = mw.Close()
	x := r.do("POST", path, token, mw.FormDataContentType(), &buf)
	return x.status, decode(x.body)
}

func (r *runner) folder(token, name, parent string) (string, int) {
	body := map[string]any{"kind": "folder", "name": name}
	if parent != "" {
		body["parent_id"] = parent
	}
	s, m := r.js("POST", "/api/nodes", token, body)
	return str(m, "id"), s
}

func (r *runner) putFile(token, folder, name string, content []byte) (id, sha string, status int, m map[string]any) {
	status, m = r.upload(token, "/api/nodes/"+folder+"/files", name, content)
	if status == 201 {
		id = str(sub(m, "node"), "id")
		sha = str(m, "sha256")
	}
	return
}

func (r *runner) acl(token, node, subjType, subj, perm, effect string) (int, string) {
	s, m := r.js("POST", "/api/nodes/"+node+"/acl", token, map[string]any{
		"subject_type": subjType, "subject_id": subj, "permission": perm, "effect": effect})
	return s, str(m, "id")
}

func (r *runner) eff(token, node, userID string) (map[string]bool, int) {
	p := "/api/nodes/" + node + "/effective-permissions"
	if userID != "" {
		p += "?user_id=" + userID
	}
	s, m := r.js("GET", p, token, nil)
	out := map[string]bool{}
	for k, v := range sub(m, "permissions") {
		b, _ := v.(bool)
		out[k] = b
	}
	return out, s
}

func (r *runner) downloadLink(token, fileID string) (int, string) {
	s, m := r.js("POST", "/api/files/"+fileID+"/download-link", token, nil)
	return s, str(m, "url")
}

func (r *runner) download(token, fileID string, version int) (int, []byte) {
	s, link := r.downloadLink(token, fileID)
	if s != 200 {
		return s, nil
	}
	if version > 0 {
		link += "&version=" + strconv.Itoa(version)
	}
	x := r.do("GET", link, "", "", nil)
	return x.status, x.body
}

func (r *runner) shareCreate(token, node string, body map[string]any) (int, map[string]any) {
	return r.js("POST", "/api/nodes/"+node+"/share-links", token, body)
}
func (r *runner) shareGet(tok string) response {
	return r.do("GET", "/api/s/"+tok+"/download", "", "", nil)
}
func (r *runner) sharePost(tok, pw string) response {
	b, _ := json.Marshal(map[string]string{"password": pw})
	return r.do("POST", "/api/s/"+tok+"/download", "", "application/json", bytes.NewReader(b))
}

func (r *runner) parallel(n int, f func(i int)) {
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			f(i)
		}(i)
	}
	wg.Wait()
}

func (r *runner) dbCount(q string, args ...any) int64 {
	var n int64
	if err := r.db.QueryRow(r.ctx, q, args...).Scan(&n); err != nil {
		return -1
	}
	return n
}

// mustFail: sorguyu bir transaction icinde dener ve her durumda geri alir.
func (r *runner) mustFail(q string) bool {
	tx, err := r.db.Begin(r.ctx)
	if err != nil {
		return false
	}
	defer func() { _ = tx.Rollback(r.ctx) }()
	_, err = tx.Exec(r.ctx, q)
	return err != nil
}

func (r *runner) blobExists(sha string) bool {
	if len(sha) != 64 {
		return false
	}
	_, err := os.Stat(filepath.Join(r.storage, "blobs", sha[:2], sha))
	return err == nil
}

func (r *runner) auditActions(token string, after int64) map[string]int {
	counts := map[string]int{}
	cur := after
	for page := 0; page < 40; page++ {
		s, m := r.js("GET", fmt.Sprintf("/api/audit?after=%d&limit=200", cur), token, nil)
		if s != 200 {
			counts["__error"]++
			break
		}
		for _, it := range list(m, "items") {
			mm, _ := it.(map[string]any)
			counts[str(mm, "action")]++
			counts["__total"]++
		}
		next, ok := m["next_cursor"].(float64)
		if !ok {
			break
		}
		cur = int64(next)
	}
	return counts
}

func (r *runner) ensureDocType() string {
	if r.docType != "" {
		return r.docType
	}
	code := "v" + r.run
	s, _ := r.js("POST", "/api/document-types", r.tok["arsiv"],
		map[string]any{"code": code, "name": "Dogrulama (0 gun)", "retention_days": 0})
	if s == 201 || s == 409 {
		r.docType = code
	}
	return r.docType
}

func (r *runner) assign(fileID, docType string) int {
	s, _ := r.js("PUT", "/api/files/"+fileID+"/retention", r.tok["arsiv"], map[string]any{"doc_type": docType})
	return s
}

// ---------------------------------------------------------------- testler

func (r *runner) tHealth() {
	x := r.do("GET", "/health", "", "", nil)
	m := decode(x.body)
	r.check("HEALTH", "GET /health 200 ve veritabani up", x.status == 200 && str(m, "database") == "up",
		"durum=%d govde=%s", x.status, x.body)
}

func (r *runner) tAuth() {
	s, m := r.js("POST", "/api/auth/login", "", map[string]string{"email": "admin@kasadoc.local", "password": "yanlis"})
	r.check("AUTH", "yanlis parola 401 invalid_credentials", s == 401 && errCode(m) == "invalid_credentials",
		"durum=%d kod=%s", s, errCode(m))
	s, m = r.js("POST", "/api/auth/login", "", map[string]string{"email": "yok@kasadoc.local", "password": "x"})
	r.check("AUTH", "bilinmeyen e-posta ayni hatayi doner", s == 401 && errCode(m) == "invalid_credentials",
		"durum=%d kod=%s", s, errCode(m))
	s, _ = r.js("POST", "/api/auth/login", "", map[string]string{"email": "", "password": ""})
	r.check("AUTH", "bos bilgiyle giris 400", s == 400, "durum=%d", s)

	for _, a := range accounts {
		s, m := r.js("POST", "/api/auth/login", "", map[string]string{"email": a.email, "password": demoPassword})
		ok := s == 200 && str(m, "role") == a.role && str(m, "access_token") != ""
		r.check("AUTH", "giris: "+a.key+" ("+a.role+")", ok, "durum=%d rol=%s", s, str(m, "role"))
		if ok {
			r.tok[a.key] = str(m, "access_token")
			r.refresh[a.key] = str(m, "refresh_token")
			_, me := r.js("GET", "/api/me", r.tok[a.key], nil)
			r.userID[a.key] = str(me, "id")
		}
	}
	s, m = r.js("GET", "/api/me", r.tok["calisan"], nil)
	r.check("AUTH", "/api/me dogru kullaniciyi doner", s == 200 && str(m, "email") == "calisan@kasadoc.local",
		"durum=%d", s)
	r.check("AUTH", "belirteci olmayan istek 401", r.code("GET", "/api/me", "") == 401, "401 bekleniyordu")
	r.check("AUTH", "bozuk belirtec 401", r.code("GET", "/api/me", "abc.def.ghi") == 401, "401 bekleniyordu")

	s, m = r.js("POST", "/api/auth/refresh", "", map[string]string{"refresh_token": r.refresh["calisan"]})
	newTok := str(m, "access_token")
	r.check("AUTH", "refresh ile yeni access token alinir", s == 200 && newTok != "" && r.code("GET", "/api/me", newTok) == 200,
		"durum=%d", s)
	s, _ = r.js("POST", "/api/auth/refresh", "", map[string]string{"refresh_token": r.tok["calisan"]})
	r.check("AUTH", "access token refresh olarak kullanilamaz", s == 401, "durum=%d", s)
	r.check("AUTH", "refresh token access olarak kullanilamaz", r.code("GET", "/api/me", r.refresh["calisan"]) == 401,
		"401 bekleniyordu")
}

func (r *runner) tRBAC() {
	emp := r.tok["calisan"]
	rootBody := map[string]any{"kind": "folder", "name": "x-" + r.run}
	cases := []struct {
		name, method, path, token string
		body                      any
		want                      int
	}{
		{"anonim /api/nodes 401", "GET", "/api/nodes", "", nil, 401},
		{"calisan admin ucu 403", "GET", "/api/admin/ping", emp, nil, 403},
		{"admin admin ucu 200", "GET", "/api/admin/ping", r.tok["admin"], nil, 200},
		{"calisan denetim kaydi 403", "GET", "/api/audit", emp, nil, 403},
		{"denetci denetim kaydi 200", "GET", "/api/audit", r.tok["denetci"], nil, 200},
		{"calisan zincir dogrulama 403", "GET", "/api/audit/verify", emp, nil, 403},
		{"calisan karantina listesi 403", "GET", "/api/quarantine", emp, nil, 403},
		{"calisan imha calistirma 403", "POST", "/api/retention/run", emp, nil, 403},
		{"hukuk imha calistirma 403", "POST", "/api/retention/run", r.tok["hukuk"], nil, 403},
		{"calisan grup olusturma 403", "POST", "/api/groups", emp, map[string]any{"name": "x"}, 403},
		{"calisan belge turu ekleme 403", "POST", "/api/document-types", emp, map[string]any{"code": "xx"}, 403},
		{"calisan hukuki bekletme 403", "POST", "/api/nodes/00000000-0000-0000-0000-000000000001/legal-holds", emp, map[string]any{"case_ref": "x"}, 403},
		{"calisan kok klasor olusturma 403", "POST", "/api/nodes", emp, rootBody, 403},
		{"yonetici imha calistirma 403", "POST", "/api/retention/run", r.tok["yonetici"], nil, 403},
	}
	for _, c := range cases {
		s, _ := r.js(c.method, c.path, c.token, c.body)
		r.check("RBAC", c.name, s == c.want, "beklenen %d, gelen %d", c.want, s)
	}
}

func (r *runner) tF1() {
	adm, emp := r.tok["admin"], r.tok["calisan"]
	root, s := r.folder(adm, "vfy-"+r.run+"-f1", "")
	r.check("F-1", "kok klasor olusturma (201)", s == 201 && root != "", "durum=%d", s)
	child, s := r.folder(adm, "alt", root)
	r.check("F-1", "alt klasor olusturma (201)", s == 201 && child != "", "durum=%d", s)
	_, s = r.folder(adm, "alt", root)
	r.check("F-1", "ayni klasorde ayni ad 409", s == 409, "durum=%d", s)
	_, s = r.folder(adm, "a/b", root)
	r.check("F-1", "gecersiz klasor adi 400", s == 400, "durum=%d", s)

	fid, _, s, _ := r.putFile(adm, child, "belge.txt", []byte("f1 icerik "+r.run+"\n"))
	r.check("F-1", "dosya yukleme (201)", s == 201 && fid != "", "durum=%d", s)
	_, m := r.js("GET", "/api/nodes?parent_id="+root, adm, nil)
	r.check("F-1", "klasor listesinde alt klasor gorunur", hasName(itemNames(m), "alt"), "liste=%v", itemNames(m))
	_, m = r.js("GET", "/api/nodes?parent_id="+child, adm, nil)
	r.check("F-1", "alt klasor listesinde dosya gorunur", hasName(itemNames(m), "belge.txt"), "liste=%v", itemNames(m))

	for i := 1; i <= 3; i++ {
		r.folder(adm, fmt.Sprintf("sayfa-%d", i), root)
	}
	_, p1 := r.js("GET", "/api/nodes?parent_id="+root+"&limit=2", adm, nil)
	cur := str(p1, "next_cursor")
	_, p2 := r.js("GET", "/api/nodes?parent_id="+root+"&limit=2&after="+cur, adm, nil)
	r.check("F-1", "anahtar kumeli sayfalama (2+2, imlec zinciri)",
		len(itemNames(p1)) == 2 && cur != "" && len(itemNames(p2)) == 2 && str(p2, "next_cursor") == "",
		"sayfa1=%v imlec=%q sayfa2=%v", itemNames(p1), cur, itemNames(p2))

	_, m = r.js("GET", "/api/nodes?parent_id="+root, emp, nil)
	r.check("F-1", "yetkisiz kullanici bos liste gorur", len(itemNames(m)) == 0, "liste=%v", itemNames(m))
	s, _ = r.upload(emp, "/api/nodes/"+child+"/files", "izinsiz.txt", []byte("x"))
	r.check("F-1", "yazma yetkisi olmayan yukleyemez (403)", s == 403, "durum=%d", s)
	s, _ = r.upload(adm, "/api/nodes/"+fid+"/files", "x.txt", []byte("x"))
	r.check("F-1", "dosyanin altina dosya yuklenemez (400)", s == 400, "durum=%d", s)
}

func (r *runner) tF2() {
	adm, emp := r.tok["admin"], r.tok["calisan"]
	root, _ := r.folder(adm, "vfy-"+r.run+"-f2", "")
	v1 := []byte("surum bir " + r.run + "\n")
	v2 := []byte("surum iki, farkli icerik " + r.run + "\n")
	fid, _, s, _ := r.putFile(adm, root, "plan.txt", v1)
	r.check("F-2", "ilk yukleme (surum 1)", s == 201, "durum=%d", s)
	vp := "/api/files/" + fid + "/versions"

	s, m := r.upload(adm, vp, "plan.txt", v2)
	r.check("F-2", "yeni surum yukleme (surum 2)", s == 201 && num(m, "version_no") == 2, "durum=%d %v", s, m)
	st, b := r.download(adm, fid, 0)
	r.check("F-2", "son surum indirilir (v2)", st == 200 && bytes.Equal(b, v2), "durum=%d", st)
	st, b = r.download(adm, fid, 1)
	r.check("F-2", "eski surum indirilir (v1)", st == 200 && bytes.Equal(b, v1), "durum=%d", st)

	s, m = r.js("POST", vp+"/1/restore", adm, nil)
	r.check("F-2", "eski surume donus yeni surum uretir (3)", s == 201 && num(m, "version_no") == 3 && num(m, "restored_from") == 1,
		"durum=%d %v", s, m)
	st, b = r.download(adm, fid, 0)
	r.check("F-2", "donusten sonra son surum v1 icerigidir", st == 200 && bytes.Equal(b, v1), "durum=%d", st)
	st, b = r.download(adm, fid, 2)
	r.check("F-2", "gecmis korunur: surum 2 hala v2", st == 200 && bytes.Equal(b, v2), "durum=%d", st)

	s, m = r.upload(adm, vp, "plan.pdf", []byte("%PDF-1.4 x"))
	r.check("F-2", "farkli uzantili surum reddedilir (415)", s == 415 && errCode(m) == "extension_mismatch", "durum=%d %v", s, m)
	s, _ = r.upload(emp, vp, "plan.txt", v2)
	r.check("F-2", "yazma yetkisiz yeni surum yukleyemez (403)", s == 403, "durum=%d", s)
	r.check("F-2", "yetkisiz surum listesi 403", r.code("GET", vp, emp) == 403, "403 bekleniyordu")
	r.check("F-2", "olmayan surum geri yuklenemez (404)", r.code("POST", vp+"/99/restore", adm) == 404, "404 bekleniyordu")
	s, m = r.upload(adm, vp, "plan.txt", []byte("x\nKASADOC-TEST-MALWARE\n"))
	r.check("F-2", "zararli surum karantinaya alinir (422)", s == 422 && errCode(m) == "malware_detected", "durum=%d %v", s, m)

	var mu sync.Mutex
	nos := map[int]bool{}
	fails := 0
	r.parallel(5, func(i int) {
		s, m := r.upload(adm, vp, "plan.txt", []byte(fmt.Sprintf("eszamanli %s %d\n", r.run, i)))
		mu.Lock()
		defer mu.Unlock()
		if s != 201 {
			fails++
			return
		}
		nos[num(m, "version_no")] = true
	})
	r.check("F-2", "eszamanli 5 yukleme: surum numaralari benzersiz", fails == 0 && len(nos) == 5, "hata=%d benzersiz=%d", fails, len(nos))
	_, m = r.js("GET", vp, adm, nil)
	r.check("F-2", "surum listesi 8 kayit icerir", len(list(m, "items")) == 8, "kayit=%d", len(list(m, "items")))
}

func (r *runner) tF3() {
	adm, emp := r.tok["admin"], r.tok["calisan"]
	empID := r.userID["calisan"]
	root, _ := r.folder(adm, "vfy-"+r.run+"-f3", "")
	fname := "ara-" + r.run + ".txt"
	fid, _, _, _ := r.putFile(adm, root, fname, []byte("f3 "+r.run+"\n"))
	tag := "t" + r.run
	tp := "/api/nodes/" + fid + "/tags"

	s, m := r.js("POST", tp, adm, map[string]any{"tag": strings.ToUpper(tag)})
	r.check("F-3", "etiket ekleme (201, kucuk harfe cevrilir)", s == 201 && str(m, "tag") == tag, "durum=%d %v", s, m)
	s, _ = r.js("POST", tp, adm, map[string]any{"tag": tag})
	r.check("F-3", "var olan etiket 200", s == 200, "durum=%d", s)
	s, _ = r.js("POST", tp, adm, map[string]any{"tag": "bad tag!"})
	r.check("F-3", "gecersiz etiket 400", s == 400, "durum=%d", s)
	s, _ = r.js("POST", tp, emp, map[string]any{"tag": "x"})
	r.check("F-3", "yetkisiz etiket ekleyemez (403)", s == 403, "durum=%d", s)

	_, m = r.js("GET", "/api/search?tag="+tag, adm, nil)
	r.check("F-3", "etikete gore arama", len(itemNames(m)) == 1 && itemNames(m)[0] == fname, "sonuc=%v", itemNames(m))
	_, m = r.js("GET", "/api/search?q=ARA-"+r.run+"&kind=file", adm, nil)
	r.check("F-3", "ada gore arama (buyuk/kucuk harf duyarsiz)", len(itemNames(m)) == 1, "sonuc=%v", itemNames(m))
	_, m = r.js("GET", "/api/search?q=ara-"+r.run+"&kind=folder", adm, nil)
	r.check("F-3", "tur filtresi (klasor) dosyayi disarida birakir", len(itemNames(m)) == 0, "sonuc=%v", itemNames(m))
	_, m = r.js("GET", "/api/search?q=%25", adm, nil)
	r.check("F-3", "LIKE joker karakteri kacirilir", len(itemNames(m)) == 0, "sonuc=%v", itemNames(m))
	r.check("F-3", "gecersiz limit 400", r.code("GET", "/api/search?limit=0", adm) == 400, "400 bekleniyordu")

	_, m = r.js("GET", "/api/search?q=ara-"+r.run, emp, nil)
	r.check("F-3", "yetkisiz kullanici sonuc gormez", len(itemNames(m)) == 0, "sonuc=%v", itemNames(m))
	r.acl(adm, root, "user", empID, "read", "allow")
	_, m = r.js("GET", "/api/search?q=ara-"+r.run, emp, nil)
	r.check("F-3", "miras alinan yetkiyle sonuc gorunur", len(itemNames(m)) == 1, "sonuc=%v", itemNames(m))
	r.acl(adm, fid, "user", empID, "read", "deny")
	_, m = r.js("GET", "/api/search?q=ara-"+r.run, emp, nil)
	r.check("F-3", "deny kazanir: sonuc gizlenir", len(itemNames(m)) == 0, "sonuc=%v", itemNames(m))

	r.check("F-3", "etiket kaldirma (204)", r.code("DELETE", tp+"/"+tag, adm) == 204, "204 bekleniyordu")
	r.check("F-3", "tekrar kaldirma 404", r.code("DELETE", tp+"/"+tag, adm) == 404, "404 bekleniyordu")
	_, m = r.js("GET", "/api/search?tag="+tag, adm, nil)
	r.check("F-3", "etiket kalkinca sonuc yok", len(itemNames(m)) == 0, "sonuc=%v", itemNames(m))
}

func (r *runner) tF4() {
	adm, emp, hukuk := r.tok["admin"], r.tok["calisan"], r.tok["hukuk"]
	empID := r.userID["calisan"]
	root, _ := r.folder(adm, "vfy-"+r.run+"-f4", "")
	content := []byte("f4 paylasim " + r.run + "\n")
	fid, _, _, _ := r.putFile(adm, root, "paylas.txt", content)

	s, _ := r.acl(adm, fid, "user", empID, "read", "allow")
	r.check("F-4", "kisiye yetki verme (200)", s == 200, "durum=%d", s)
	st, b := r.download(emp, fid, 0)
	r.check("F-4", "yetkili kisi indirir", st == 200 && bytes.Equal(b, content), "durum=%d", st)
	st, _ = r.download(hukuk, fid, 0)
	r.check("F-4", "yetkisiz kisi indiremez (403)", st == 403, "durum=%d", st)

	gfolder, _ := r.folder(adm, "vfy-"+r.run+"-f4g", "")
	s, m := r.js("POST", "/api/groups", adm, map[string]any{"name": "vfy-grp-" + r.run})
	gid := str(m, "id")
	r.check("F-4", "grup olusturma (201)", s == 201 && gid != "", "durum=%d", s)
	s, _ = r.js("POST", "/api/groups/"+gid+"/members", adm, map[string]any{"user_id": empID})
	r.check("F-4", "gruba uye ekleme (204)", s == 204, "durum=%d", s)
	r.acl(adm, gfolder, "group", gid, "write", "allow")
	p, _ := r.eff(adm, gfolder, empID)
	r.check("F-4", "grup yetkisi uyeye gecer", p["write"], "write=%v", p["write"])
	s, _ = r.js("DELETE", "/api/groups/"+gid+"/members/"+empID, adm, nil)
	p, _ = r.eff(adm, gfolder, empID)
	r.check("F-4", "uyelik kalkinca yetki aninda biter", s == 204 && !p["write"], "durum=%d write=%v", s, p["write"])

	s, m = r.shareCreate(adm, fid, map[string]any{"expires_in_seconds": 3600})
	tok, lid := str(m, "token"), str(m, "id")
	r.check("F-4", "sureli baglanti olusturma (201)", s == 201 && tok != "", "durum=%d %v", s, m)
	info := r.do("GET", "/api/s/"+tok, "", "", nil)
	r.check("F-4", "baglanti bilgisi kimliksiz okunur", info.status == 200, "durum=%d", info.status)
	dl := r.shareGet(tok)
	r.check("F-4", "baglantidan kimliksiz indirme", dl.status == 200 && bytes.Equal(dl.body, content), "durum=%d", dl.status)
	s, _ = r.shareCreate(emp, fid, map[string]any{"expires_in_seconds": 3600})
	r.check("F-4", "paylasim yetkisi olmayan baglanti olusturamaz (403)", s == 403, "durum=%d", s)
	r.check("F-4", "baglanti iptali (204)", r.code("DELETE", "/api/share-links/"+lid, adm) == 204, "204 bekleniyordu")
	r.check("F-4", "iptal edilen baglanti 410", r.shareGet(tok).status == 410, "410 bekleniyordu")
}

func (r *runner) tF5() {
	adm, arsiv, hukuk := r.tok["admin"], r.tok["arsiv"], r.tok["hukuk"]
	_, m := r.js("GET", "/api/document-types", arsiv, nil)
	types := map[string]int{}
	for _, it := range list(m, "items") {
		mm, _ := it.(map[string]any)
		types[str(mm, "code")] = num(mm, "retention_days")
	}
	r.check("F-5", "varsayilan belge turleri (sozlesme 3650, rapor 1825, yazisma 730 gun)",
		types["contract"] == 3650 && types["report"] == 1825 && types["correspondence"] == 730, "turler=%v", types)

	code := r.ensureDocType()
	r.check("F-5", "belge turu olusturma (arsiv sorumlusu)", code != "", "belge turu olusturulamadi")

	root, _ := r.folder(adm, "vfy-"+r.run+"-f5", "")
	long, _, _, _ := r.putFile(adm, root, "sozlesme.txt", []byte("uzun sureli "+r.run+"\n"))
	s, m := r.js("PUT", "/api/files/"+long+"/retention", arsiv, map[string]any{"doc_type": "contract"})
	until, err := time.Parse(time.RFC3339Nano, str(m, "retention_until"))
	r.check("F-5", "sozlesme 10 yil saklanir (bitis tarihi hesaplanir)",
		s == 200 && err == nil && until.After(time.Now().AddDate(9, 0, 0)), "durum=%d bitis=%s", s, str(m, "retention_until"))
	run0 := r.js
	_ = run0

	fid, _, _, _ := r.putFile(adm, root, "imha-adayi.txt", []byte("f5 imha "+r.run+"\n"))
	s, m = r.js("POST", "/api/nodes/"+root+"/legal-holds", hukuk, map[string]any{"case_ref": "DAVA-" + r.run, "reason": "dogrulama"})
	holdID := str(m, "id")
	r.check("F-5", "hukuki bekletme koyma (201)", s == 201 && holdID != "", "durum=%d %v", s, m)
	r.check("F-5", "saklama kaydi atama (200)", r.assign(fid, code) == 200, "200 bekleniyordu")
	r.check("F-5", "ikinci atama 409", r.assign(fid, code) == 409, "409 bekleniyordu")
	r.check("F-5", "bilinmeyen belge turu 400", r.assign(fid, "yok"+r.run) == 400, "400 bekleniyordu")
	s, _ = r.js("PUT", "/api/files/"+fid+"/retention", r.tok["calisan"], map[string]any{"doc_type": code})
	r.check("F-5", "calisan saklama kaydi atayamaz (403)", s == 403, "durum=%d", s)

	s, m = r.js("POST", "/api/retention/run", arsiv, nil)
	r.check("F-5", "bekletme imhayi engeller (blocked_by_hold >= 1)", s == 200 && num(m, "blocked_by_hold") >= 1, "durum=%d %v", s, m)
	_, m = r.js("GET", "/api/files/"+fid+"/retention", arsiv, nil)
	r.check("F-5", "bekletme altindaki dosya durur", m["destroyed_at"] == nil && m["legal_hold_active"] == true, "%v", m)
	st, _ := r.download(adm, fid, 0)
	r.check("F-5", "bekletme altindaki dosya hala indirilebilir", st == 200, "durum=%d", st)

	s1 := r.code("POST", "/api/legal-holds/"+holdID+"/release", hukuk)
	s2 := r.code("POST", "/api/legal-holds/"+holdID+"/release", hukuk)
	r.check("F-5", "bekletme kaldirma (204, tekrar 204)", s1 == 204 && s2 == 204, "%d %d", s1, s2)
	s, m = r.js("POST", "/api/retention/run", arsiv, nil)
	r.check("F-5", "bekletme kalkinca belge imha edilir", s == 200 && num(m, "destroyed") >= 1 && len(list(m, "certificates")) >= 1, "durum=%d %v", s, m)
	_, m = r.js("GET", "/api/files/"+fid+"/retention", arsiv, nil)
	r.check("F-5", "imha edilen dosya isaretlenir (destroyed_at)", m["destroyed_at"] != nil, "%v", m)
	st, _ = r.download(adm, fid, 0)
	r.check("F-5", "imha edilen dosya indirilemez (404)", st == 404, "durum=%d", st)
	_, m = r.js("GET", "/api/nodes?parent_id="+root, adm, nil)
	r.check("F-5", "imha edilen dosya listede gorunmez", !hasName(itemNames(m), "imha-adayi.txt") && hasName(itemNames(m), "sozlesme.txt"), "liste=%v", itemNames(m))
}

func (r *runner) tF6() {
	adm, emp, mgr := r.tok["admin"], r.tok["calisan"], r.tok["yonetici"]
	empID := r.userID["calisan"]
	root, _ := r.folder(adm, "vfy-"+r.run+"-f6", "")
	f1, _, _, _ := r.putFile(adm, root, "teklif1.txt", []byte("t1 "+r.run+"\n"))
	f2, _, _, _ := r.putFile(adm, root, "teklif2.txt", []byte("t2 "+r.run+"\n"))
	r.acl(adm, f1, "user", empID, "read", "allow")
	r.acl(adm, f1, "user", empID, "write", "allow")
	reqPath := func(f string) string { return "/api/files/" + f + "/approval-requests" }
	decide := func(token, id, d string) (int, map[string]any) {
		return r.js("POST", "/api/approval-requests/"+id+"/decide", token, map[string]any{"decision": d, "comment": "dogrulama"})
	}

	s, m := r.js("POST", reqPath(f1), emp, map[string]any{"note": "incelemeye hazir"})
	id1 := str(m, "id")
	r.check("F-6", "onay talebi olusturma (201, pending)", s == 201 && str(m, "status") == "pending", "durum=%d %v", s, m)
	s, _ = r.js("POST", reqPath(f1), emp, map[string]any{"note": "tekrar"})
	r.check("F-6", "ayni dosya icin ikinci bekleyen talep 409", s == 409, "durum=%d", s)
	s, _ = r.js("POST", reqPath(f2), emp, map[string]any{"note": "x"})
	r.check("F-6", "yazma yetkisiz talep acamaz (403)", s == 403, "durum=%d", s)

	s, _ = decide(emp, id1, "approve")
	r.check("F-6", "calisan karar veremez (403)", s == 403, "durum=%d", s)
	s, _ = decide("", id1, "approve")
	r.check("F-6", "anonim karar veremez (401)", s == 401, "durum=%d", s)
	s, _ = decide(mgr, id1, "belki")
	r.check("F-6", "gecersiz karar 400", s == 400, "durum=%d", s)

	_, m = r.js("GET", "/api/approval-requests?status=pending", mgr, nil)
	found := false
	for _, it := range list(m, "items") {
		mm, _ := it.(map[string]any)
		if str(mm, "id") == id1 {
			found = true
		}
	}
	r.check("F-6", "yonetici bekleyen talebi gorur", found, "talep listede yok")
	s, m = decide(mgr, id1, "approve")
	r.check("F-6", "yonetici onaylar (200)", s == 200 && str(m, "status") == "approved", "durum=%d %v", s, m)
	s, m = decide(mgr, id1, "reject")
	r.check("F-6", "ikinci karar 409 already_decided", s == 409 && errCode(m) == "already_decided", "durum=%d %v", s, m)

	s, m = r.js("POST", reqPath(f2), adm, map[string]any{"note": "kendi talebim"})
	id2 := str(m, "id")
	s2, m2 := decide(adm, id2, "approve")
	r.check("F-6", "kendi talebini onaylayamaz (gorev ayriligi)", s == 201 && s2 == 403 && errCode(m2) == "self_approval", "durum=%d/%d %v", s, s2, m2)
	s, m = decide(mgr, id2, "reject")
	r.check("F-6", "yonetici reddeder (200)", s == 200 && str(m, "status") == "rejected", "durum=%d %v", s, m)

	_, m = r.js("POST", reqPath(f1), emp, map[string]any{"note": "yaris"})
	id3 := str(m, "id")
	var mu sync.Mutex
	wins, conflicts, other := 0, 0, 0
	r.parallel(8, func(i int) {
		d := "approve"
		if i%2 == 1 {
			d = "reject"
		}
		c, _ := decide(mgr, id3, d)
		mu.Lock()
		defer mu.Unlock()
		switch c {
		case 200:
			wins++
		case 409:
			conflicts++
		default:
			other++
		}
	})
	r.check("F-6", "eszamanli 8 karardan yalnizca biri kazanir", wins == 1 && conflicts == 7 && other == 0, "kazanan=%d cakisma=%d diger=%d", wins, conflicts, other)
}

func (r *runner) tT1() {
	adm, emp := r.tok["admin"], r.tok["calisan"]
	empID := r.userID["calisan"]
	chain := make([]string, 0, 10)
	parent := ""
	okChain := true
	for i := 0; i < 10; i++ {
		id, s := r.folder(adm, fmt.Sprintf("vfy-%s-t1-l%d", r.run, i+1), parent)
		if s != 201 {
			okChain = false
			break
		}
		chain = append(chain, id)
		parent = id
	}
	r.check("T-1", "10 seviyelik klasor zinciri kurulur", okChain, "zincir kurulamadi")
	if !okChain {
		return
	}
	deep := chain[9]

	p, s := r.eff(emp, deep, "")
	r.check("T-1", "yetki yokken etkin yetki bos", s == 200 && !p["read"] && !p["write"], "durum=%d %v", s, p)
	s, e1 := r.acl(adm, chain[0], "user", empID, "read", "allow")
	p, _ = r.eff(emp, deep, "")
	r.check("T-1", "kokteki read 10 seviye asagiya miras kalir", s == 200 && p["read"] && !p["write"], "durum=%d %v", s, p)
	_, m := r.js("GET", "/api/nodes?parent_id="+chain[8], emp, nil)
	r.check("T-1", "miras alinan yetkiyle derin klasor listelenir", hasName(itemNames(m), fmt.Sprintf("vfy-%s-t1-l10", r.run)), "liste=%v", itemNames(m))

	s, e2 := r.acl(adm, chain[4], "user", empID, "read", "deny")
	p, _ = r.eff(emp, deep, "")
	pMid, _ := r.eff(emp, chain[3], "")
	r.check("T-1", "ortadaki deny altini kapatir, ustunu etkilemez", s == 200 && !p["read"] && pMid["read"], "derin=%v ust=%v", p["read"], pMid["read"])
	_, m = r.js("GET", "/api/nodes?parent_id="+chain[8], emp, nil)
	r.check("T-1", "deny altindaki klasor listeden gizlenir", len(itemNames(m)) == 0, "liste=%v", itemNames(m))
	_, e3 := r.acl(adm, deep, "user", empID, "read", "allow")
	p, _ = r.eff(emp, deep, "")
	r.check("T-1", "deny her zaman kazanir (alttaki allow aşamaz)", !p["read"], "read=%v", p["read"])
	s = r.code("DELETE", "/api/nodes/"+chain[4]+"/acl/"+e2, adm)
	p, _ = r.eff(emp, deep, "")
	r.check("T-1", "deny kaldirilinca yetki aninda geri gelir (onbellek yok)", s == 204 && p["read"], "durum=%d read=%v", s, p["read"])

	_, gm := r.js("POST", "/api/groups", adm, map[string]any{"name": "vfy-t1-" + r.run})
	gid := str(gm, "id")
	r.js("POST", "/api/groups/"+gid+"/members", adm, map[string]any{"user_id": empID})
	r.acl(adm, chain[6], "group", gid, "read", "deny")
	p, _ = r.eff(emp, deep, "")
	r.check("T-1", "grup deny kullanici allow'unu gecersiz kilar", !p["read"], "read=%v", p["read"])
	r.js("DELETE", "/api/groups/"+gid+"/members/"+empID, adm, nil)
	p, _ = r.eff(emp, deep, "")
	r.check("T-1", "gruptan cikinca yetki aninda geri gelir", p["read"], "read=%v", p["read"])

	s, _ = r.acl(emp, chain[0], "user", empID, "write", "allow")
	r.check("T-1", "manage yetkisiz yetki veremez (403)", s == 403, "durum=%d", s)
	r.check("T-1", "baskasinin etkin yetkisi sorgulanamaz (403)", r.code("GET", "/api/nodes/"+deep+"/effective-permissions?user_id="+r.userID["admin"], emp) == 403, "403 bekleniyordu")
	pAdm, s := r.eff(adm, deep, empID)
	r.check("T-1", "yonetici baska kullanicinin etkin yetkisini gorur", s == 200 && pAdm["read"], "durum=%d %v", s, pAdm)

	var lat []time.Duration
	for i := 0; i < 220; i++ {
		st := time.Now()
		r.js("GET", "/api/nodes/"+deep+"/effective-permissions", emp, nil)
		if i >= 20 {
			lat = append(lat, time.Since(st))
		}
	}
	p95 := pct(lat, 0.95)
	fmt.Printf("T-1 olcum (HTTP, 10 seviye, ~110k dugumlu veritabani): n=%d p50=%v p95=%v p99=%v\n",
		len(lat), pct(lat, 0.5).Round(10*time.Microsecond), p95.Round(10*time.Microsecond), pct(lat, 0.99).Round(10*time.Microsecond))
	r.check("T-1", "etkin yetki sorgusu p95 < 30 ms", p95 < 30*time.Millisecond, "p95=%v", p95)

	content := []byte("t1 derin dosya " + r.run + "\n")
	fid, _, _, _ := r.putFile(adm, deep, "t1.txt", content)
	st1, link := r.downloadLink(emp, fid)
	x := r.do("GET", link, "", "", nil)
	r.check("T-1", "yetkili kullanici derin dosyayi indirir", st1 == 200 && x.status == 200 && bytes.Equal(x.body, content), "durum=%d/%d", st1, x.status)
	r.code("DELETE", "/api/nodes/"+chain[0]+"/acl/"+e1, adm)
	r.code("DELETE", "/api/nodes/"+deep+"/acl/"+e3, adm)
	x = r.do("GET", link, "", "", nil)
	r.check("T-1", "yetki kaldirilinca eski baglanti calismaz (403)", x.status == 403, "durum=%d", x.status)
	st2, _ := r.downloadLink(emp, fid)
	r.check("T-1", "yetki kaldirilinca yeni baglanti da alinamaz (403)", st2 == 403, "durum=%d", st2)
}

func (r *runner) tT2() {
	adm, emp, den := r.tok["admin"], r.tok["calisan"], r.tok["denetci"]
	empID := r.userID["calisan"]
	root, _ := r.folder(adm, "vfy-"+r.run+"-t2", "")
	other, _ := r.folder(adm, "vfy-"+r.run+"-t2b", "")
	content := []byte("t2 icerik " + r.run + "\n")
	want := shaOf(content)

	id1, sha1, s, _ := r.putFile(adm, root, "a.txt", content)
	r.check("T-2", "yukleme: SHA-256 sunucuda dogru hesaplanir", s == 201 && sha1 == want, "durum=%d sha=%s", s, sha1)
	id2, _, s, m := r.putFile(adm, other, "b.txt", content)
	blobs := r.dbCount(`SELECT count(*) FROM blobs WHERE sha256 = $1`, want)
	vers := r.dbCount(`SELECT count(*) FROM file_versions WHERE sha256 = $1`, want)
	r.check("T-2", "ayni icerik tek kopya, iki ayri dosya", s == 201 && m["deduplicated"] == true && blobs == 1 && vers == 2 && id1 != id2,
		"durum=%d blob=%d surum=%d", s, blobs, vers)
	r.check("T-2", "icerik adresli yolda diskte duruyor", r.blobExists(want), "blobs/%s/%s bulunamadi", want[:2], want)

	r.acl(adm, id1, "user", empID, "read", "allow")
	s1, _ := r.downloadLink(emp, id1)
	s2, _ := r.downloadLink(emp, id2)
	r.check("T-2", "ayni icerikte yetkiler ayri (biri 200, digeri 403)", s1 == 200 && s2 == 403, "%d / %d", s1, s2)

	st, link := r.downloadLink(adm, id1)
	x := r.do("GET", link, "", "", nil)
	r.check("T-2", "imzali baglantiyla indirme (kimliksiz), guvenlik basliklari",
		st == 200 && x.status == 200 && bytes.Equal(x.body, content) &&
			x.header.Get("X-Content-Type-Options") == "nosniff" && strings.HasPrefix(x.header.Get("Content-Disposition"), "attachment"),
		"durum=%d/%d", st, x.status)
	if i := strings.LastIndex(link, "&sig="); i >= 0 && len(link) > i+6 {
		sig := link[i+5:]
		bad := "A"
		if sig[:1] == "A" {
			bad = "B"
		}
		x = r.do("GET", link[:i+5]+bad+sig[1:], "", "", nil)
		r.check("T-2", "kurcalanmis imza reddedilir (403)", x.status == 403, "durum=%d", x.status)
	} else {
		r.check("T-2", "kurcalanmis imza reddedilir (403)", false, "baglanti imza icermiyor: %s", link)
	}
	swapped := strings.Replace(link, "uid="+r.userID["admin"], "uid="+r.userID["hukuk"], 1)
	r.check("T-2", "baskasi adina imza kullanilamaz (403)", r.do("GET", swapped, "", "", nil).status == 403, "403 bekleniyordu")

	mal := []byte("merhaba\nKASADOC-TEST-MALWARE\n" + r.run)
	qBefore := r.dbCount(`SELECT count(*) FROM quarantine_items`)
	s, m = r.upload(adm, "/api/nodes/"+root+"/files", "temiz-gorunen.txt", mal)
	qAfter := r.dbCount(`SELECT count(*) FROM quarantine_items`)
	r.check("T-2", "zararli imzali dosya karantinaya alinir (422)", s == 422 && errCode(m) == "malware_detected" && qAfter >= qBefore+1,
		"durum=%d karantina %d -> %d", s, qBefore, qAfter)
	r.check("T-2", "karantinadaki icerik blob olarak kaydedilmez", r.dbCount(`SELECT count(*) FROM blobs WHERE sha256 = $1`, shaOf(mal)) == 0 && !r.blobExists(shaOf(mal)), "blob olusmus")
	s, m = r.upload(adm, "/api/nodes/"+root+"/files", "paket.zip", makeZip(map[string][]byte{"gizli.txt": mal}))
	r.check("T-2", "arsiv icindeki zararli imza yakalanir (422)", s == 422 && errCode(m) == "malware_detected", "durum=%d %v", s, m)
	sq, mq := r.js("GET", "/api/quarantine", den, nil)
	r.check("T-2", "denetci karantina listesini gorur", sq == 200 && len(list(mq, "items")) >= 1, "durum=%d", sq)

	s, m = r.upload(adm, "/api/nodes/"+root+"/files", "fatura.pdf", append([]byte("MZ\x90\x00"), make([]byte, 64)...))
	r.check("T-2", "exe imzali .pdf reddedilir (magic byte, 415)", s == 415 && errCode(m) == "content_mismatch", "durum=%d %v", s, m)
	s, m = r.upload(adm, "/api/nodes/"+root+"/files", "betik.exe", []byte("MZ"))
	r.check("T-2", "izin verilmeyen uzanti 415", s == 415 && errCode(m) == "unsupported_extension", "durum=%d %v", s, m)
	s, m = r.upload(adm, "/api/nodes/"+root+"/files", "uzantisiz", []byte("abc"))
	r.check("T-2", "uzantisiz dosya 415", s == 415, "durum=%d %v", s, m)

	s, m = r.upload(adm, "/api/nodes/"+root+"/files", "../../evil.txt", []byte("zararsiz metin "+r.run))
	name := str(sub(m, "node"), "name")
	r.check("T-2", "yol gezinmesi iceren ad etkisiz (sadelestirilir veya reddedilir)",
		(s == 201 && name != "" && !strings.ContainsAny(name, `/\`)) || s == 400, "durum=%d ad=%q", s, name)

	bomb := makeZip(map[string][]byte{"[Content_Types].xml": []byte("<x/>"), "sifir.bin": make([]byte, 8<<20)})
	s, m = r.upload(adm, "/api/nodes/"+root+"/files", "bomba.docx", bomb)
	r.check("T-2", "ZIP bombasi reddedilir (422 archive_rejected)", s == 422 && errCode(m) == "archive_rejected", "durum=%d %v", s, m)
	s, m = r.upload(adm, "/api/nodes/"+root+"/files", "slip.zip", makeZip(map[string][]byte{"../evil.txt": []byte("x")}))
	r.check("T-2", "zip-slip reddedilir (422 archive_rejected)", s == 422 && errCode(m) == "archive_rejected", "durum=%d %v", s, m)
	s, _ = r.upload(adm, "/api/nodes/"+root+"/files", "belge.docx", makeZip(map[string][]byte{"[Content_Types].xml": []byte("<x/>"), "word/document.xml": []byte("<d/>")}))
	r.check("T-2", "gecerli docx yapisi kabul edilir", s == 201, "durum=%d", s)
}

func (r *runner) tT3() {
	adm, emp := r.tok["admin"], r.tok["calisan"]
	empID := r.userID["calisan"]
	root, _ := r.folder(adm, "vfy-"+r.run+"-t3", "")
	content := []byte("t3 paylasilan icerik " + r.run + "\n")
	fid, _, _, _ := r.putFile(adm, root, "paylas.txt", content)
	var secrets []string

	mk := func(body map[string]any) (string, string) {
		s, m := r.shareCreate(adm, fid, body)
		if s != 201 {
			return "", ""
		}
		secrets = append(secrets, str(m, "token"))
		return str(m, "token"), str(m, "id")
	}

	tok, _ := mk(map[string]any{"expires_in_seconds": 3600})
	h := shaOf([]byte(tok))
	r.check("T-3", "token 43 karakter base64url (256 bit rastgele)", validTok(tok), "token=%q", tok)
	r.check("T-3", "veritabaninda yalnizca hash saklanir",
		r.dbCount(`SELECT count(*) FROM share_links WHERE token_hash = $1`, h) == 1 &&
			r.dbCount(`SELECT count(*) FROM share_links WHERE token_hash = $1`, tok) == 0, "ham token veya hash eksik")
	info := r.do("GET", "/api/s/"+tok, "", "", nil)
	r.check("T-3", "bilgi ucu parola gereksinimini bildirir", info.status == 200 && decode(info.body)["requires_password"] == false, "durum=%d", info.status)

	pw := "Sifre-12345"
	secrets = append(secrets, pw)
	tokP, _ := mk(map[string]any{"expires_in_seconds": 3600, "password": pw})
	r.check("T-3", "parolali baglanti parolasiz GET ile 401", r.shareGet(tokP).status == 401, "401 bekleniyordu")
	x := r.sharePost(tokP, "yanlis-parola")
	r.check("T-3", "yanlis parola 401 invalid_password", x.status == 401 && errCode(decode(x.body)) == "invalid_password", "durum=%d", x.status)
	x = r.sharePost(tokP, pw)
	r.check("T-3", "dogru parola ile indirme", x.status == 200 && bytes.Equal(x.body, content), "durum=%d", x.status)

	tokM, _ := mk(map[string]any{"expires_in_seconds": 3600, "max_downloads": 2})
	a, b2, c := r.shareGet(tokM).status, r.shareGet(tokM).status, r.shareGet(tokM).status
	r.check("T-3", "indirme sayisi siniri (2 izinli, 3. istek 410)", a == 200 && b2 == 200 && c == 410, "%d %d %d", a, b2, c)

	tokC, _ := mk(map[string]any{"expires_in_seconds": 3600, "max_downloads": 3})
	var mu sync.Mutex
	okN, goneN, otherN := 0, 0, 0
	r.parallel(10, func(i int) {
		st := r.shareGet(tokC).status
		mu.Lock()
		defer mu.Unlock()
		switch st {
		case 200:
			okN++
		case 410:
			goneN++
		default:
			otherN++
		}
	})
	r.check("T-3", "eszamanli 10 istekte sinir asilmaz (3 basarili, 7 reddedilen)", okN == 3 && goneN == 7 && otherN == 0,
		"basarili=%d reddedilen=%d diger=%d", okN, goneN, otherN)

	pwB := "Dogru-Parola-1"
	secrets = append(secrets, pwB)
	tokB, _ := mk(map[string]any{"expires_in_seconds": 3600, "password": pwB})
	allWrong := true
	for i := 0; i < 5; i++ {
		if r.sharePost(tokB, fmt.Sprintf("yanlis-%d", i)).status != 401 {
			allWrong = false
		}
	}
	x = r.sharePost(tokB, "yanlis-son")
	r.check("T-3", "brute-force: 5 hatali denemeden sonra 429 ve Retry-After", allWrong && x.status == 429 && x.header.Get("Retry-After") != "",
		"ilk5=%v durum=%d retry=%q", allWrong, x.status, x.header.Get("Retry-After"))
	x = r.sharePost(tokB, pwB)
	r.check("T-3", "kilitliyken dogru parola da 429", x.status == 429, "durum=%d", x.status)

	tokE, _ := mk(map[string]any{"expires_in_seconds": 3600})
	_, derr := r.db.Exec(r.ctx, `UPDATE share_links SET expires_at = now() - interval '1 minute' WHERE token_hash = $1`, shaOf([]byte(tokE)))
	r.check("T-3", "suresi dolan baglanti 410", derr == nil && r.shareGet(tokE).status == 410, "hata=%v", derr)

	tokR, idR := mk(map[string]any{"expires_in_seconds": 3600})
	r.check("T-3", "yetkisiz kisi baglanti iptal edemez (403)", r.code("DELETE", "/api/share-links/"+idR, emp) == 403, "403 bekleniyordu")
	r.check("T-3", "iptal (204, tekrar 204)", r.code("DELETE", "/api/share-links/"+idR, adm) == 204 && r.code("DELETE", "/api/share-links/"+idR, adm) == 204, "204 bekleniyordu")
	r.check("T-3", "iptal edilen baglanti 410", r.shareGet(tokR).status == 410, "410 bekleniyordu")

	r.check("T-3", "bilinmeyen token 404", r.shareGet(strings.Repeat("A", 43)).status == 404, "404 bekleniyordu")
	r.check("T-3", "bozuk bicimli token 404", r.shareGet("kisa").status == 404, "404 bekleniyordu")

	r.acl(adm, fid, "user", empID, "read", "allow")
	_, shareEntry := r.acl(adm, fid, "user", empID, "share", "allow")
	_ = shareEntry
	s, m := r.shareCreate(emp, fid, map[string]any{"expires_in_seconds": 3600})
	tokX := str(m, "token")
	secrets = append(secrets, tokX)
	r.check("T-3", "paylasim yetkisiyle calisan baglanti olusturur", s == 201 && tokX != "", "durum=%d", s)
	var readEntry string
	_ = r.db.QueryRow(r.ctx, `SELECT id::text FROM acl_entries WHERE node_id = $1::uuid AND subject_id = $2::uuid AND permission = 'read'`, fid, empID).Scan(&readEntry)
	before := r.shareGet(tokX).status
	r.code("DELETE", "/api/nodes/"+fid+"/acl/"+readEntry, adm)
	after := r.shareGet(tokX).status
	r.check("T-3", "olusturan okuma yetkisini kaybedince baglanti kapanir", before == 200 && after == 410, "%d -> %d", before, after)

	for _, body := range []map[string]any{
		{"expires_in_seconds": 10}, {"expires_in_seconds": 99999999},
		{"expires_in_seconds": 3600, "max_downloads": 0}, {"expires_in_seconds": 3600, "password": "kisa"},
	} {
		r.check("T-3", fmt.Sprintf("gecersiz parametre reddedilir %v", body), func() bool {
			st, _ := r.shareCreate(adm, fid, body)
			return st == 400
		}(), "400 bekleniyordu")
	}

	var leaks int64
	for _, sec := range secrets {
		if sec == "" {
			continue
		}
		n := r.dbCount(`SELECT count(*) FROM audit_log WHERE position($1 in new_value) > 0 OR position($1 in old_value) > 0
OR position($1 in target_id) > 0 OR position($1 in actor_id) > 0`, sec)
		if n != 0 {
			leaks++
		}
	}
	r.check("T-3", "ham token ve parolalar denetim kaydinda yok", leaks == 0, "%d sir denetim kaydinda bulundu", leaks)
}

func (r *runner) tT4() {
	adm, arsiv, den := r.tok["admin"], r.tok["arsiv"], r.tok["denetci"]
	code := r.ensureDocType()
	root, _ := r.folder(adm, "vfy-"+r.run+"-t4", "")

	s, m := r.js("GET", "/api/audit/verify", den, nil)
	r.check("T-4", "zincir dogrulama ucu: valid=true, kayit var", s == 200 && m["valid"] == true && num(m, "checked") > 0, "durum=%d %v", s, m)
	for _, q := range []string{
		`UPDATE audit_log SET action = 'x' WHERE seq = (SELECT min(seq) FROM audit_log)`,
		`DELETE FROM audit_log WHERE seq = (SELECT min(seq) FROM audit_log)`,
		`TRUNCATE audit_log`,
	} {
		r.check("T-4", "degistirilemez kayit engeli: "+strings.Fields(q)[0], r.mustFail(q), "sorgu basarili oldu (geri alindi)")
	}

	content := []byte("t4 imha " + r.run + "\n")
	fid, sha, s, _ := r.putFile(adm, root, "imha.txt", content)
	before := r.blobExists(sha)
	r.check("T-4", "imhadan once icerik diskte", s == 201 && before, "durum=%d", s)
	r.check("T-4", "saklama kaydi atanir", r.assign(fid, code) == 200, "200 bekleniyordu")

	s, m = r.js("POST", "/api/retention/run", arsiv, nil)
	certs := list(m, "certificates")
	cert := ""
	if len(certs) > 0 {
		cert, _ = certs[0].(string)
	}
	r.check("T-4", "imha job'i belgeyi imha eder, tutanak uretir", s == 200 && num(m, "destroyed") >= 1 && cert != "", "durum=%d %v", s, m)
	r.check("T-4", "icerik diskten gercekten silinir", !r.blobExists(sha), "blob hala diskte")
	r.check("T-4", "surum ve blob kayitlari silinir",
		r.dbCount(`SELECT count(*) FROM file_versions WHERE node_id = $1::uuid`, fid) == 0 &&
			r.dbCount(`SELECT count(*) FROM blobs WHERE sha256 = $1`, sha) == 0, "kayit kaldi")

	s, m = r.js("GET", "/api/destruction-certificates/"+cert, arsiv, nil)
	ver := sub(m, "verification")
	r.check("T-4", "tutanak: govde hash'i ve denetim kaydi dogrulanir", s == 200 && ver["valid"] == true, "durum=%d %v", s, ver)
	vs := list(sub(m, "body"), "versions")
	hasSHA := false
	if len(vs) > 0 {
		v0, _ := vs[0].(map[string]any)
		hasSHA = str(v0, "sha256") == sha && v0["blob_removed"] == true
	}
	r.check("T-4", "tutanak icerik hash'ini ve silinme kaydini tasir", hasSHA, "surumler=%v", vs)

	s, m = r.js("POST", "/api/retention/run", arsiv, nil)
	r.check("T-4", "idempotent: tekrar calistirma hicbir sey imha etmez", s == 200 && num(m, "destroyed") == 0, "durum=%d %v", s, m)

	_, e1 := r.db.Exec(r.ctx, `UPDATE destruction_certificates SET body = body || ' ' WHERE id = $1::uuid`, cert)
	_, m = r.js("GET", "/api/destruction-certificates/"+cert, arsiv, nil)
	tamperDetected := e1 == nil && sub(m, "verification")["valid"] == false
	_, e2 := r.db.Exec(r.ctx, `UPDATE destruction_certificates SET body = left(body, length(body) - 1) WHERE id = $1::uuid`, cert)
	_, m = r.js("GET", "/api/destruction-certificates/"+cert, arsiv, nil)
	r.check("T-4", "tutanak kurcalanmasi fark edilir (geri alininca gecerli)", tamperDetected && e2 == nil && sub(m, "verification")["valid"] == true,
		"tespit=%v hata=%v/%v", tamperDetected, e1, e2)

	sharedContent := []byte("t4 ortak icerik " + r.run + "\n")
	s1id, sSHA, _, _ := r.putFile(adm, root, "ortak1.txt", sharedContent)
	s2id, _, _, _ := r.putFile(adm, root, "ortak2.txt", sharedContent)
	r.assign(s1id, code)
	_, m = r.js("POST", "/api/retention/run", arsiv, nil)
	stillThere := r.blobExists(sSHA)
	r.assign(s2id, code)
	r.js("POST", "/api/retention/run", arsiv, nil)
	r.check("T-4", "ortak blob son kullanici imha edilene kadar korunur", num(m, "destroyed") >= 1 && stillThere && !r.blobExists(sSHA),
		"ilk imhadan sonra blob=%v, sonunda blob=%v", stillThere, r.blobExists(sSHA))

	for i := 0; i < 4; i++ {
		id, _, _, _ := r.putFile(adm, root, fmt.Sprintf("es-%d.txt", i), []byte(fmt.Sprintf("t4 eszamanli %s %d\n", r.run, i)))
		r.assign(id, code)
	}
	var mu sync.Mutex
	total := 0
	uniq := map[string]bool{}
	failed := 0
	r.parallel(3, func(i int) {
		st, rm := r.js("POST", "/api/retention/run", arsiv, nil)
		mu.Lock()
		defer mu.Unlock()
		if st != 200 {
			failed++
			return
		}
		total += num(rm, "destroyed")
		for _, c := range list(rm, "certificates") {
			if id, ok := c.(string); ok {
				uniq[id] = true
			}
		}
	})
	r.check("T-4", "3 eszamanli imha job'i: her belge tam bir kez imha edilir", failed == 0 && total >= 4 && total == len(uniq),
		"hata=%d toplam=%d benzersiz_tutanak=%d", failed, total, len(uniq))

	s, m = r.js("GET", "/api/audit/verify", den, nil)
	r.check("T-4", "tum islemlerden sonra zincir hala gecerli", s == 200 && m["valid"] == true, "durum=%d %v", s, m)
}

func (r *runner) tAudit() {
	den := r.tok["denetci"]
	s, m := r.js("GET", "/api/audit?limit=5", den, nil)
	r.check("F-7", "denetci denetim kayitlarini listeler (anahtar kumeli)", s == 200 && len(list(m, "items")) > 0, "durum=%d", s)
	if items := list(m, "items"); len(items) > 0 {
		it, _ := items[0].(map[string]any)
		r.check("F-7", "kayit kim/ne zaman/neyi alanlarini tasir", str(it, "actor_id") != "" && str(it, "ts") != "" && str(it, "action") != "" && str(it, "hash") != "",
			"kayit=%v", it)
	}
	r.check("F-7", "calisan denetim kaydina giremez (403)", r.code("GET", "/api/audit", r.tok["calisan"]) == 403, "403 bekleniyordu")
	r.check("F-7", "zincir dogrulama ucu yalnizca denetci/admin", r.code("GET", "/api/audit/verify", r.tok["calisan"]) == 403, "403 bekleniyordu")

	c := r.auditActions(den, r.baseline)
	r.check("F-7", "denetim kayitlari sayfalanarak okunur", c["__error"] == 0 && c["__total"] > 50, "toplam=%d hata=%d", c["__total"], c["__error"])
	need := []struct {
		id, action string
		min        int
	}{
		{"F-7", "file.upload", 5}, {"F-7", "file.download", 3}, {"F-7", "file.version_added", 2},
		{"F-7", "file.version_restored", 1}, {"F-7", "acl.set", 3}, {"F-7", "acl.revoke", 1},
		{"F-7", "tag.added", 1}, {"F-7", "tag.removed", 1},
		{"F-7", "approval.requested", 3}, {"F-7", "approval.approved", 1}, {"F-7", "approval.rejected", 1},
		{"F-5", "doctype.created", 1}, {"F-5", "retention.assigned", 3}, {"F-5", "legal_hold.placed", 1}, {"F-5", "legal_hold.released", 1},
		{"T-2", "upload.quarantined", 2},
		{"T-3", "share.created", 5}, {"T-3", "share.view", 1}, {"T-3", "share.download", 3}, {"T-3", "share.denied", 3}, {"T-3", "share.revoked", 1},
		{"T-4", "retention.blocked_by_hold", 1}, {"T-4", "retention.destroyed", 4}, {"T-4", "retention.run", 1},
	}
	for _, n := range need {
		r.check(n.id, "denetim kaydi yazildi: "+n.action, c[n.action] >= n.min, "bulunan=%d beklenen>=%d", c[n.action], n.min)
	}
}

// ---------------------------------------------------------------- calistirma

func (r *runner) waitHealthy() {
	for i := 0; i < 60; i++ {
		if r.do("GET", "/health", "", "", nil).status == 200 {
			return
		}
		time.Sleep(time.Second)
	}
}

func (r *runner) waitSeed() {
	deadline := time.Now().Add(150 * time.Second)
	announced := false
	for time.Now().Before(deadline) {
		var v string
		if err := r.db.QueryRow(r.ctx, `SELECT value FROM sim_state WHERE key = 'seeded'`).Scan(&v); err == nil {
			fmt.Println("simulator seed hazir:", v)
			return
		}
		if !announced {
			fmt.Println("simulator seed'i bekleniyor...")
			announced = true
		}
		time.Sleep(2 * time.Second)
	}
	fmt.Println("UYARI: simulator seed'i tamamlanmadi, dogrulama seed'siz devam ediyor")
}

func (r *runner) report(d time.Duration) int {
	fmt.Println()
	fmt.Println("KasaDoc dogrulama sonucu")
	fmt.Println(strings.Repeat("=", 72))
	fmt.Printf("%-7s %-6s %-8s %s\n", "KIMLIK", "SONUC", "ADIM", "ACIKLAMA")
	fmt.Println(strings.Repeat("-", 72))
	failedIDs := 0
	for _, o := range order {
		total, passed := 0, 0
		for _, c := range r.results {
			if c.id == o.id {
				total++
				if c.ok {
					passed++
				}
			}
		}
		status := "PASS"
		if total == 0 || passed != total {
			status = "FAIL"
			failedIDs++
		}
		fmt.Printf("%-7s %-6s %3d/%-4d %s\n", o.id, status, passed, total, o.title)
	}
	fmt.Println(strings.Repeat("-", 72))
	nFail := 0
	for _, c := range r.results {
		if !c.ok {
			nFail++
			fmt.Printf("BASARISIZ [%s] %s\n    -> %s\n", c.id, c.name, c.detail)
		}
	}
	if os.Getenv("VERIFY_VERBOSE") != "" {
		for _, c := range r.results {
			if c.ok {
				fmt.Printf("ok [%s] %s\n", c.id, c.name)
			}
		}
	}
	fmt.Printf("%d adim, %d basarisiz, sure %s\n", len(r.results), nFail, d.Round(time.Millisecond))
	if failedIDs > 0 {
		fmt.Println("SONUC: FAIL")
		return 1
	}
	fmt.Println("SONUC: PASS")
	return 0
}

func connectDB(ctx context.Context, dsn string) (*pgxpool.Pool, error) {
	var last error
	for i := 0; i < 30; i++ {
		pool, err := pgxpool.New(ctx, dsn)
		if err == nil {
			if err = pool.Ping(ctx); err == nil {
				return pool, nil
			}
			pool.Close()
		}
		last = err
		time.Sleep(2 * time.Second)
	}
	return nil, last
}

func main() {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		fmt.Println("DATABASE_URL tanimli degil")
		os.Exit(2)
	}
	ctx := context.Background()
	pool, err := connectDB(ctx, dsn)
	if err != nil {
		fmt.Println("veritabanina baglanilamadi:", err)
		os.Exit(2)
	}
	defer pool.Close()

	r := &runner{
		api: env("API_URL", "http://backend:8080"), storage: env("STORAGE_DIR", "/data/storage"),
		run: strconv.FormatInt(time.Now().UnixNano(), 36), cl: &http.Client{Timeout: 60 * time.Second},
		db: pool, ctx: ctx, tok: map[string]string{}, refresh: map[string]string{}, userID: map[string]string{},
	}
	fmt.Println("dogrulama kimligi:", r.run)
	r.waitHealthy()
	r.waitSeed()
	r.baseline = r.dbCount(`SELECT COALESCE(max(seq), 0) FROM audit_log`)

	started := time.Now()
	steps := []struct {
		id string
		fn func()
	}{
		{"HEALTH", r.tHealth}, {"AUTH", r.tAuth}, {"RBAC", r.tRBAC},
		{"F-1", r.tF1}, {"F-2", r.tF2}, {"F-3", r.tF3}, {"F-4", r.tF4}, {"F-5", r.tF5}, {"F-6", r.tF6},
		{"T-1", r.tT1}, {"T-2", r.tT2}, {"T-3", r.tT3}, {"T-4", r.tT4}, {"F-7", r.tAudit},
	}
	for _, st := range steps {
		fmt.Printf("calisiyor: %s\n", st.id)
		r.safe(st.id, st.fn)
	}
	os.Exit(r.report(time.Since(started)))
}
