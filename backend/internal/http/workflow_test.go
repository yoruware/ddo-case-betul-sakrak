package httpapi_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"mime/multipart"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/yoruware/ddo-case-betul-sakrak/backend/internal/audit"
	"github.com/yoruware/ddo-case-betul-sakrak/backend/internal/upload"

	"context"
)

func contentSHA(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func (e *env) uploadTo(token, path, filename string, content []byte) (int, map[string]any) {
	e.t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormFile("file", filename)
	if err != nil {
		e.t.Fatal(err)
	}
	_, _ = fw.Write(content)
	_ = mw.Close()
	resp, body := e.do("POST", path, token, &buf, mw.FormDataContentType())
	return resp.StatusCode, decode(body)
}

// fetch: indirme bağlantısı alıp dosyayı indirir (version=0 son sürüm).
func (e *env) fetch(token, fileID string, version int) (int, []byte) {
	e.t.Helper()
	c, m := e.js("POST", "/api/files/"+fileID+"/download-link", token, nil)
	if c != 200 {
		return c, nil
	}
	link := str(m, "url")
	if version > 0 {
		link += "&version=" + strconv.Itoa(version)
	}
	resp, body := e.do("GET", link, "", nil, "")
	return resp.StatusCode, body
}

func (e *env) grant(fileID, userID, perm string) {
	e.t.Helper()
	c, r := e.js("POST", "/api/nodes/"+fileID+"/acl", e.admin, map[string]any{
		"subject_type": "user", "subject_id": userID, "permission": perm, "effect": "allow"})
	if c != 200 {
		e.t.Fatalf("yetki verilemedi: %d %v", c, r)
	}
}

func itemNames(m map[string]any) []string {
	items, _ := m["items"].([]any)
	out := []string{}
	for _, it := range items {
		mm, _ := it.(map[string]any)
		out = append(out, str(mm, "name"))
	}
	return out
}

func hasName(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func chainValid(t *testing.T, e *env) {
	t.Helper()
	res, err := audit.New(e.pool).Verify(context.Background())
	if err != nil || !res.Valid {
		t.Fatalf("denetim zinciri geçerli olmalı: %+v %v", res, err)
	}
}

func TestSurumleme(t *testing.T) {
	e := newEnv(t)
	root := e.folder("Surum", "")
	v1 := []byte("birinci surum icerigi\n")
	v2 := []byte("ikinci surum icerigi, farkli\n")
	code, m := e.upload(e.admin, root, "plan.txt", v1)
	if code != 201 {
		t.Fatalf("yükleme başarısız: %d %v", code, m)
	}
	file := nodeID(m)
	vpath := "/api/files/" + file + "/versions"

	t.Run("yeni sürüm yüklenir", func(t *testing.T) {
		c, r := e.uploadTo(e.admin, vpath, "plan.txt", v2)
		if c != 201 || num(r, "version_no") != 2 {
			t.Fatalf("201 ve version_no=2 bekleniyordu: %d %v", c, r)
		}
	})

	t.Run("sürüm listesi sıralı ve doğru hash'li", func(t *testing.T) {
		c, r := e.js("GET", vpath, e.admin, nil)
		items, _ := r["items"].([]any)
		if c != 200 || len(items) != 2 {
			t.Fatalf("2 sürüm bekleniyordu: %d %v", c, r)
		}
		first, _ := items[0].(map[string]any)
		if num(first, "version_no") != 1 || str(first, "sha256") != contentSHA(v1) {
			t.Fatalf("ilk sürüm beklenmedik: %v", first)
		}
	})

	t.Run("son sürüm indirilir, eski sürüm istenebilir", func(t *testing.T) {
		if c, b := e.fetch(e.admin, file, 0); c != 200 || !bytes.Equal(b, v2) {
			t.Fatalf("son sürüm v2 olmalı: %d %q", c, b)
		}
		if c, b := e.fetch(e.admin, file, 1); c != 200 || !bytes.Equal(b, v1) {
			t.Fatalf("1. sürüm v1 olmalı: %d %q", c, b)
		}
	})

	t.Run("eski sürüme dönüş yeni sürüm üretir, geçmiş korunur", func(t *testing.T) {
		c, r := e.js("POST", "/api/files/"+file+"/versions/1/restore", e.admin, nil)
		if c != 201 || num(r, "version_no") != 3 || num(r, "restored_from") != 1 {
			t.Fatalf("3. sürüm bekleniyordu: %d %v", c, r)
		}
		if c, b := e.fetch(e.admin, file, 0); c != 200 || !bytes.Equal(b, v1) {
			t.Fatalf("son sürüm v1 içeriği olmalı: %d %q", c, b)
		}
		if c, b := e.fetch(e.admin, file, 2); c != 200 || !bytes.Equal(b, v2) {
			t.Fatalf("2. sürüm hâlâ v2 olmalı: %d %q", c, b)
		}
		if n := e.count(`SELECT count(*) FROM file_versions WHERE node_id = $1::uuid`, file); n != 3 {
			t.Fatalf("3 sürüm bekleniyordu, gelen %d", n)
		}
	})

	t.Run("geçersiz ve yetkisiz istekler", func(t *testing.T) {
		if c, _ := e.js("POST", "/api/files/"+file+"/versions/99/restore", e.admin, nil); c != 404 {
			t.Fatalf("olmayan sürüm 404 olmalı: %d", c)
		}
		if c, r := e.uploadTo(e.admin, vpath, "plan.pdf", []byte("%PDF-1.4 x")); c != 415 || errCode(r) != "extension_mismatch" {
			t.Fatalf("farklı uzantı 415 olmalı: %d %v", c, r)
		}
		if c, _ := e.uploadTo(e.emp, vpath, "plan.txt", v2); c != 403 {
			t.Fatalf("yazma yetkisiz 403 olmalı: %d", c)
		}
		if c, _ := e.js("GET", vpath, e.emp, nil); c != 403 {
			t.Fatalf("okuma yetkisiz 403 olmalı: %d", c)
		}
		if c, _ := e.js("POST", "/api/files/"+file+"/versions/1/restore", e.emp, nil); c != 403 {
			t.Fatalf("geri yükleme yetkisiz 403 olmalı: %d", c)
		}
		if c, _ := e.js("GET", "/api/files/00000000-0000-0000-0000-000000000009/versions", e.admin, nil); c != 404 {
			t.Fatalf("olmayan dosya 404 olmalı: %d", c)
		}
	})

	t.Run("zararlı sürüm karantinaya alınır, sürüm eklenmez", func(t *testing.T) {
		qBefore := e.count(`SELECT count(*) FROM quarantine_items`)
		c, r := e.uploadTo(e.admin, vpath, "plan.txt", append([]byte("x\n"), upload.EICAR()...))
		if c != 422 || errCode(r) != upload.CodeMalware {
			t.Fatalf("422 malware_detected bekleniyordu: %d %v", c, r)
		}
		if n := e.count(`SELECT count(*) FROM quarantine_items`); n != qBefore+1 {
			t.Fatalf("karantina kaydı artmalı: %d -> %d", qBefore, n)
		}
		if n := e.count(`SELECT count(*) FROM file_versions WHERE node_id = $1::uuid`, file); n != 3 {
			t.Fatalf("sürüm sayısı değişmemeli, gelen %d", n)
		}
	})

	t.Run("eşzamanlı sürüm yüklemelerinde numara çakışmaz", func(t *testing.T) {
		var mu sync.Mutex
		var wg sync.WaitGroup
		nos := map[int]bool{}
		fails := 0
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				c, r := e.uploadTo(e.admin, vpath, "plan.txt", []byte(fmt.Sprintf("eszamanli surum %d\n", i)))
				mu.Lock()
				defer mu.Unlock()
				if c != 201 {
					fails++
					return
				}
				nos[num(r, "version_no")] = true
			}(i)
		}
		wg.Wait()
		if fails != 0 || len(nos) != 8 {
			t.Fatalf("8 benzersiz sürüm bekleniyordu: hata=%d benzersiz=%d", fails, len(nos))
		}
		if n := e.count(`SELECT count(DISTINCT version_no) FROM file_versions WHERE node_id = $1::uuid`, file); n != 11 {
			t.Fatalf("11 sürüm bekleniyordu, gelen %d", n)
		}
	})

	t.Run("denetim zincirinde", func(t *testing.T) {
		if n := e.count(`SELECT count(*) FROM audit_log WHERE action = 'file.version_added'`); n != 9 {
			t.Fatalf("9 sürüm kaydı bekleniyordu, gelen %d", n)
		}
		if n := e.count(`SELECT count(*) FROM audit_log WHERE action = 'file.version_restored'`); n != 1 {
			t.Fatalf("1 geri yükleme kaydı bekleniyordu, gelen %d", n)
		}
		chainValid(t, e)
	})
}

func TestEtiketVeArama(t *testing.T) {
	e := newEnv(t)
	root := e.folder("Aranan", "")
	sub := e.folder("Alt_Klasor", root)
	e.folder("AltXKlasor", root)
	code, m := e.upload(e.admin, sub, "Rapor-2026.txt", []byte("rapor icerigi\n"))
	if code != 201 {
		t.Fatalf("yükleme başarısız: %d %v", code, m)
	}
	file := nodeID(m)
	search := func(token, qs string) (int, map[string]any) { return e.js("GET", "/api/search?"+qs, token, nil) }
	tagPath := "/api/nodes/" + file + "/tags"

	t.Run("etiket ekleme ve doğrulama", func(t *testing.T) {
		c, r := e.js("POST", tagPath, e.admin, map[string]any{"tag": "Gizli"})
		if c != 201 || str(r, "tag") != "gizli" {
			t.Fatalf("201 ve küçük harfli etiket bekleniyordu: %d %v", c, r)
		}
		if c, _ := e.js("POST", tagPath, e.admin, map[string]any{"tag": "gizli"}); c != 200 {
			t.Fatalf("var olan etiket 200 olmalı: %d", c)
		}
		if c, _ := e.js("POST", tagPath, e.admin, map[string]any{"tag": "bad tag!"}); c != 400 {
			t.Fatalf("geçersiz etiket 400 olmalı: %d", c)
		}
		if c, _ := e.js("POST", tagPath, e.emp, map[string]any{"tag": "x"}); c != 403 {
			t.Fatalf("yetkisiz 403 olmalı: %d", c)
		}
		c, r = e.js("GET", tagPath, e.admin, nil)
		tags, _ := r["tags"].([]any)
		if c != 200 || len(tags) != 1 || tags[0] != "gizli" {
			t.Fatalf("tek etiket bekleniyordu: %d %v", c, r)
		}
	})

	t.Run("ada, etikete ve türe göre arama", func(t *testing.T) {
		if _, r := search(e.admin, "q=rapor"); !hasName(itemNames(r), "Rapor-2026.txt") {
			t.Fatalf("büyük/küçük harf duyarsız arama çalışmalı: %v", r)
		}
		if _, r := search(e.admin, "tag=Gizli"); len(itemNames(r)) != 1 || itemNames(r)[0] != "Rapor-2026.txt" {
			t.Fatalf("etiket araması tek sonuç vermeli: %v", r)
		}
		if _, r := search(e.admin, "q=alt&kind=folder"); len(itemNames(r)) != 2 {
			t.Fatalf("2 klasör bekleniyordu: %v", r)
		}
		if _, r := search(e.admin, "q=alt&kind=file"); len(itemNames(r)) != 0 {
			t.Fatalf("dosya sonucu olmamalı: %v", r)
		}
	})

	t.Run("LIKE joker karakterleri kaçırılır", func(t *testing.T) {
		if _, r := search(e.admin, "q=Alt_Klasor"); len(itemNames(r)) != 1 || itemNames(r)[0] != "Alt_Klasor" {
			t.Fatalf("yalnızca Alt_Klasor bekleniyordu: %v", r)
		}
		if _, r := search(e.admin, "q=%25"); len(itemNames(r)) != 0 {
			t.Fatalf("'%%' joker olarak çalışmamalı: %v", r)
		}
	})

	t.Run("arama sonuçları yetkiye göre süzülür", func(t *testing.T) {
		if _, r := search(e.emp, "q=rapor"); len(itemNames(r)) != 0 {
			t.Fatalf("yetkisiz kullanıcı sonuç görmemeli: %v", r)
		}
		e.grant(root, e.empID, "read")
		if _, r := search(e.emp, "q=rapor"); len(itemNames(r)) != 1 {
			t.Fatalf("miras alınan yetkiyle 1 sonuç bekleniyordu: %v", r)
		}
		c, r := e.js("POST", "/api/nodes/"+file+"/acl", e.admin, map[string]any{
			"subject_type": "user", "subject_id": e.empID, "permission": "read", "effect": "deny"})
		if c != 200 {
			t.Fatalf("deny yazılamadı: %d %v", c, r)
		}
		if _, r := search(e.emp, "q=rapor"); len(itemNames(r)) != 0 {
			t.Fatalf("deny kazanmalı, sonuç olmamalı: %v", r)
		}
	})

	t.Run("anahtar kümeli sayfalama", func(t *testing.T) {
		for i := 1; i <= 5; i++ {
			e.folder(fmt.Sprintf("pg-%d", i), root)
		}
		seen := map[string]bool{}
		after, pages := "", 0
		for {
			qs := "q=pg-&limit=2"
			if after != "" {
				qs += "&after=" + after
			}
			c, r := search(e.admin, qs)
			if c != 200 {
				t.Fatalf("200 bekleniyordu: %d %v", c, r)
			}
			for _, n := range itemNames(r) {
				if seen[n] {
					t.Fatalf("tekrar eden sonuç: %s", n)
				}
				seen[n] = true
			}
			pages++
			nc, _ := r["next_cursor"].(string)
			if nc == "" {
				break
			}
			if pages > 5 {
				t.Fatal("sayfalama sonsuz döngüde")
			}
			after = nc
		}
		if len(seen) != 5 || pages != 3 {
			t.Fatalf("5 sonuç ve 3 sayfa bekleniyordu: %d sonuç, %d sayfa", len(seen), pages)
		}
	})

	t.Run("geçersiz parametreler", func(t *testing.T) {
		for _, qs := range []string{"limit=0", "kind=x", "after=bozuk", "tag=bad%20tag"} {
			if c, _ := search(e.admin, qs); c != 400 {
				t.Fatalf("%s için 400 bekleniyordu: %d", qs, c)
			}
		}
	})

	t.Run("etiket kaldırma", func(t *testing.T) {
		if c, _ := e.js("DELETE", tagPath+"/gizli", e.admin, nil); c != 204 {
			t.Fatalf("204 bekleniyordu: %d", c)
		}
		if c, _ := e.js("DELETE", tagPath+"/gizli", e.admin, nil); c != 404 {
			t.Fatalf("tekrar silme 404 olmalı: %d", c)
		}
		if _, r := search(e.admin, "tag=gizli"); len(itemNames(r)) != 0 {
			t.Fatalf("etiket kalkınca sonuç olmamalı: %v", r)
		}
		if n := e.count(`SELECT count(*) FROM audit_log WHERE action = 'tag.removed'`); n != 1 {
			t.Fatalf("1 kaldırma kaydı bekleniyordu, gelen %d", n)
		}
		chainValid(t, e)
	})
}

func TestOnayIsAkisi(t *testing.T) {
	e := newEnv(t)
	root := e.folder("Onay", "")
	mk := func(name string) string {
		c, m := e.upload(e.admin, root, name, []byte("icerik "+name+"\n"))
		if c != 201 {
			t.Fatalf("yükleme başarısız: %d %v", c, m)
		}
		return nodeID(m)
	}
	file1, file2, file3 := mk("teklif1.txt"), mk("teklif2.txt"), mk("teklif3.txt")
	for _, f := range []string{file1, file3} {
		e.grant(f, e.empID, "read")
		e.grant(f, e.empID, "write")
	}
	reqPath := func(f string) string { return "/api/files/" + f + "/approval-requests" }
	decide := func(token, id, decision string) (int, map[string]any) {
		return e.js("POST", "/api/approval-requests/"+id+"/decide", token,
			map[string]any{"decision": decision, "comment": "test"})
	}
	listIDs := func(token, status string) []string {
		_, m := e.js("GET", "/api/approval-requests?status="+status, token, nil)
		items, _ := m["items"].([]any)
		ids := []string{}
		for _, it := range items {
			mm, _ := it.(map[string]any)
			ids = append(ids, str(mm, "id"))
		}
		return ids
	}
	has := func(list []string, s string) bool { return hasName(list, s) }
	var req1 string

	t.Run("talep oluşturma", func(t *testing.T) {
		c, r := e.js("POST", reqPath(file1), e.emp, map[string]any{"note": "incelemeye hazır"})
		if c != 201 || str(r, "status") != "pending" {
			t.Fatalf("201 pending bekleniyordu: %d %v", c, r)
		}
		req1 = str(r, "id")
		if c, _ := e.js("POST", reqPath(file1), e.emp, map[string]any{"note": "tekrar"}); c != 409 {
			t.Fatalf("ikinci bekleyen talep 409 olmalı: %d", c)
		}
		if c, _ := e.js("POST", reqPath(file1), e.emp, map[string]any{"note": strings.Repeat("a", 501)}); c != 400 {
			t.Fatalf("uzun not 400 olmalı: %d", c)
		}
		if c, _ := e.js("POST", reqPath(file2), e.emp, map[string]any{"note": "x"}); c != 403 {
			t.Fatalf("yazma yetkisiz 403 olmalı: %d", c)
		}
	})

	t.Run("rol kontrolleri", func(t *testing.T) {
		if c, _ := decide(e.emp, req1, "approve"); c != 403 {
			t.Fatalf("çalışan karar veremez (403): %d", c)
		}
		if c, _ := decide("", req1, "approve"); c != 401 {
			t.Fatalf("anonim 401 olmalı: %d", c)
		}
		if c, _ := decide(e.manager, req1, "belki"); c != 400 {
			t.Fatalf("geçersiz karar 400 olmalı: %d", c)
		}
		if c, _ := decide(e.manager, "00000000-0000-0000-0000-000000000009", "approve"); c != 404 {
			t.Fatalf("olmayan talep 404 olmalı: %d", c)
		}
	})

	t.Run("kendi talebini karara bağlayamaz (uygulama ve veritabanı)", func(t *testing.T) {
		c, r := e.js("POST", reqPath(file2), e.admin, map[string]any{"note": "kendi talebim"})
		if c != 201 {
			t.Fatalf("talep oluşturulamadı: %d %v", c, r)
		}
		id2 := str(r, "id")
		if c, r := decide(e.admin, id2, "approve"); c != 403 || errCode(r) != "self_approval" {
			t.Fatalf("kendi talebi 403 self_approval olmalı: %d %v", c, r)
		}
		_, err := e.pool.Exec(context.Background(),
			`UPDATE approval_requests SET status = 'approved', decided_by = requested_by, decided_at = now() WHERE id = $1::uuid`, id2)
		if err == nil {
			t.Fatal("veritabanı kendi onayını reddetmeliydi (CHECK)")
		}
		if c, r := decide(e.manager, id2, "reject"); c != 200 || str(r, "status") != "rejected" {
			t.Fatalf("yönetici reddedebilmeli: %d %v", c, r)
		}
	})

	t.Run("yönetici onaylar, ikinci karar çakışır", func(t *testing.T) {
		if !has(listIDs(e.manager, "pending"), req1) || !has(listIDs(e.emp, "pending"), req1) {
			t.Fatal("bekleyen talep hem yöneticide hem sahibinde görünmeli")
		}
		if c, r := decide(e.manager, req1, "approve"); c != 200 || str(r, "status") != "approved" {
			t.Fatalf("onay 200 olmalı: %d %v", c, r)
		}
		if c, r := decide(e.manager, req1, "reject"); c != 409 || errCode(r) != "already_decided" {
			t.Fatalf("ikinci karar 409 olmalı: %d %v", c, r)
		}
		if has(listIDs(e.manager, "pending"), req1) || !has(listIDs(e.emp, "approved"), req1) {
			t.Fatal("liste durumları güncellenmeli")
		}
		if len(listIDs(e.legal, "approved")) != 0 {
			t.Fatal("ilgisiz kullanıcı başkasının talebini görmemeli")
		}
	})

	t.Run("eşzamanlı kararlarda yalnızca biri kazanır", func(t *testing.T) {
		c, r := e.js("POST", reqPath(file3), e.emp, map[string]any{"note": "yarış"})
		if c != 201 {
			t.Fatalf("talep oluşturulamadı: %d %v", c, r)
		}
		id3 := str(r, "id")
		var mu sync.Mutex
		var wg sync.WaitGroup
		wins, conflicts, other := 0, 0, 0
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				dec := "approve"
				if i%2 == 1 {
					dec = "reject"
				}
				code, _ := decide(e.manager, id3, dec)
				mu.Lock()
				defer mu.Unlock()
				switch code {
				case 200:
					wins++
				case 409:
					conflicts++
				default:
					other++
				}
			}(i)
		}
		wg.Wait()
		if wins != 1 || conflicts != 9 || other != 0 {
			t.Fatalf("1 kazanan ve 9 çakışma bekleniyordu: %d / %d / %d", wins, conflicts, other)
		}
		if n := e.count(`SELECT count(*) FROM approval_requests WHERE id = $1::uuid AND status <> 'pending'`, id3); n != 1 {
			t.Fatalf("talep tam bir kez karara bağlanmalı, gelen %d", n)
		}
	})

	t.Run("denetim zincirinde", func(t *testing.T) {
		if n := e.count(`SELECT count(*) FROM audit_log WHERE action = 'approval.requested'`); n != 3 {
			t.Fatalf("3 talep kaydı bekleniyordu, gelen %d", n)
		}
		if n := e.count(`SELECT count(*) FROM audit_log WHERE action IN ('approval.approved','approval.rejected')`); n != 3 {
			t.Fatalf("3 karar kaydı bekleniyordu, gelen %d", n)
		}
		chainValid(t, e)
	})
}
