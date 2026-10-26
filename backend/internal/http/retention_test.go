package httpapi_test

import (
	"strings"
	"testing"
)

func num(m map[string]any, k string) int { f, _ := m[k].(float64); return int(f) }

func TestSaklamImhaUclari(t *testing.T) {
	e := newEnv(t)
	root := e.folder("Arsiv", "")
	code, m := e.upload(e.admin, root, "eski.txt", []byte("imha edilecek icerik\n"))
	if code != 201 {
		t.Fatalf("yükleme başarısız: %d %v", code, m)
	}
	fileID := nodeID(m)
	var shareTok, holdID, certID string

	t.Run("yetkisiz roller reddedilir", func(t *testing.T) {
		cases := []struct {
			name, method, path, token string
			want                      int
		}{
			{"anonim imha", "POST", "/api/retention/run", "", 401},
			{"çalışan imha", "POST", "/api/retention/run", e.emp, 403},
			{"hukuk imha", "POST", "/api/retention/run", e.legal, 403},
			{"çalışan bekletme", "POST", "/api/nodes/" + root + "/legal-holds", e.emp, 403},
			{"arşiv bekletme", "POST", "/api/nodes/" + root + "/legal-holds", e.archivist, 403},
			{"çalışan tutanak listesi", "GET", "/api/destruction-certificates", e.emp, 403},
			{"çalışan saklama bilgisi", "GET", "/api/files/" + fileID + "/retention", e.emp, 403},
		}
		for _, c := range cases {
			if got, _ := e.js(c.method, c.path, c.token, nil); got != c.want {
				t.Fatalf("%s: %d bekleniyordu, gelen %d", c.name, c.want, got)
			}
		}
	})

	t.Run("belge türü yönetimi", func(t *testing.T) {
		body := map[string]any{"code": "anlik", "name": "Anında", "retention_days": 0}
		if c, r := e.js("POST", "/api/document-types", e.archivist, body); c != 201 {
			t.Fatalf("201 bekleniyordu: %d %v", c, r)
		}
		if c, _ := e.js("POST", "/api/document-types", e.archivist, body); c != 409 {
			t.Fatalf("tekrar 409 olmalı: %d", c)
		}
		if c, _ := e.js("POST", "/api/document-types", e.emp, body); c != 403 {
			t.Fatalf("çalışan 403 almalı: %d", c)
		}
		if c, _ := e.js("POST", "/api/document-types", e.archivist, map[string]any{"code": "Büyük", "name": "x", "retention_days": 1}); c != 400 {
			t.Fatalf("geçersiz kod 400 olmalı: %d", c)
		}
		if c, _ := e.js("POST", "/api/document-types", e.archivist, map[string]any{"code": "negatif", "name": "x", "retention_days": -1}); c != 400 {
			t.Fatalf("negatif süre 400 olmalı: %d", c)
		}
		resp, b := e.do("GET", "/api/document-types", e.emp, nil, "")
		if resp.StatusCode != 200 || !strings.Contains(string(b), "contract") || !strings.Contains(string(b), "anlik") {
			t.Fatalf("tür listesi eksik: %d %s", resp.StatusCode, b)
		}
	})

	t.Run("saklama kaydı atama", func(t *testing.T) {
		path := "/api/files/" + fileID + "/retention"
		if c, _ := e.js("PUT", path, e.emp, map[string]any{"doc_type": "anlik"}); c != 403 {
			t.Fatalf("çalışan 403 almalı: %d", c)
		}
		if c, _ := e.js("PUT", path, e.archivist, map[string]any{"doc_type": "yok"}); c != 400 {
			t.Fatalf("bilinmeyen tür 400 olmalı: %d", c)
		}
		if c, _ := e.js("PUT", "/api/files/00000000-0000-0000-0000-000000000001/retention", e.archivist, map[string]any{"doc_type": "anlik"}); c != 404 {
			t.Fatalf("olmayan dosya 404 olmalı: %d", c)
		}
		if c, r := e.js("PUT", path, e.archivist, map[string]any{"doc_type": "anlik"}); c != 200 {
			t.Fatalf("atama 200 olmalı: %d %v", c, r)
		}
		if c, _ := e.js("PUT", path, e.archivist, map[string]any{"doc_type": "anlik"}); c != 409 {
			t.Fatalf("ikinci atama 409 olmalı: %d", c)
		}
	})

	t.Run("hukuki bekletme imhayı engeller", func(t *testing.T) {
		c, r := e.js("POST", "/api/nodes/"+fileID+"/share-links", e.admin, map[string]any{"expires_in_seconds": 3600})
		if c != 201 {
			t.Fatalf("paylaşım bağlantısı oluşturulamadı: %d %v", c, r)
		}
		shareTok = str(r, "token")

		c, r = e.js("POST", "/api/nodes/"+root+"/legal-holds", e.legal, map[string]any{"case_ref": "DAVA-2026-1", "reason": "Devam eden dava"})
		if c != 201 {
			t.Fatalf("bekletme 201 olmalı: %d %v", c, r)
		}
		holdID = str(r, "id")

		c, r = e.js("POST", "/api/retention/run", e.archivist, nil)
		if c != 200 || num(r, "destroyed") != 0 || num(r, "blocked_by_hold") != 1 {
			t.Fatalf("imha engellenmeli: %d %v", c, r)
		}
		c, r = e.js("GET", "/api/files/"+fileID+"/retention", e.archivist, nil)
		if c != 200 || r["legal_hold_active"] != true || r["destroyed_at"] != nil {
			t.Fatalf("bekletme aktif görünmeli: %d %v", c, r)
		}
		if c, _ := e.js("POST", "/api/files/"+fileID+"/download-link", e.admin, nil); c != 200 {
			t.Fatalf("dosya erişilebilir kalmalı: %d", c)
		}
		if c, _ := e.js("GET", "/api/nodes/"+fileID+"/legal-holds", e.archivist, nil); c != 200 {
			t.Fatalf("bekletme listesi 200 olmalı: %d", c)
		}
	})

	t.Run("bekletme kalkınca imha edilir ve tutanak doğrulanır", func(t *testing.T) {
		if c, _ := e.js("POST", "/api/legal-holds/"+holdID+"/release", e.legal, nil); c != 204 {
			t.Fatalf("kaldırma 204 olmalı: %d", c)
		}
		if c, _ := e.js("POST", "/api/legal-holds/"+holdID+"/release", e.legal, nil); c != 204 {
			t.Fatalf("tekrar kaldırma 204 olmalı: %d", c)
		}
		c, r := e.js("POST", "/api/retention/run", e.archivist, nil)
		if c != 200 || num(r, "destroyed") != 1 {
			t.Fatalf("1 imha bekleniyordu: %d %v", c, r)
		}
		certs, _ := r["certificates"].([]any)
		if len(certs) != 1 {
			t.Fatalf("1 tutanak bekleniyordu: %v", r)
		}
		certID, _ = certs[0].(string)

		c, r = e.js("GET", "/api/destruction-certificates/"+certID, e.archivist, nil)
		ver, _ := r["verification"].(map[string]any)
		if c != 200 || ver["valid"] != true {
			t.Fatalf("tutanak geçerli olmalı: %d %v", c, r)
		}
		resp, b := e.do("GET", "/api/destruction-certificates", e.archivist, nil, "")
		if resp.StatusCode != 200 || !strings.Contains(string(b), certID) {
			t.Fatalf("tutanak listede olmalı: %d", resp.StatusCode)
		}
		if c, _ := e.js("POST", "/api/files/"+fileID+"/download-link", e.admin, nil); c != 404 {
			t.Fatalf("imha edilen dosya için bağlantı 404 olmalı: %d", c)
		}
		if resp, _ := e.do("GET", "/api/s/"+shareTok+"/download", "", nil, ""); resp.StatusCode != 410 {
			t.Fatalf("paylaşım bağlantısı 410 olmalı: %d", resp.StatusCode)
		}
		resp, b = e.do("GET", "/api/nodes?parent_id="+root, e.admin, nil, "")
		if resp.StatusCode != 200 || strings.Contains(string(b), fileID) {
			t.Fatalf("imha edilen dosya listede görünmemeli: %d %s", resp.StatusCode, b)
		}
		c, r = e.js("GET", "/api/audit/verify", e.admin, nil)
		if c != 200 || r["valid"] != true {
			t.Fatalf("denetim zinciri geçerli olmalı: %d %v", c, r)
		}
	})

	t.Run("imha tekrarında hiçbir şey değişmez", func(t *testing.T) {
		c, r := e.js("POST", "/api/retention/run", e.archivist, nil)
		if c != 200 || num(r, "destroyed") != 0 || num(r, "checked") != 0 {
			t.Fatalf("boş çalıştırma bekleniyordu: %d %v", c, r)
		}
	})
}
