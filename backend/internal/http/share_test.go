package httpapi_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/yoruware/ddo-case-betul-sakrak/backend/internal/audit"
)

func tokenHash(tok string) string {
	s := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(s[:])
}

func TestPaylasimBaglantilari(t *testing.T) {
	e := newEnv(t)
	root := e.folder("Paylasim", "")
	content := []byte("paylasilacak gizli icerik\n")
	code, m := e.upload(e.admin, root, "paylas.txt", content)
	if code != 201 {
		t.Fatalf("yükleme başarısız: %d %v", code, m)
	}
	fileID := nodeID(m)

	var allTokens []string
	mustCreate := func(body map[string]any) (string, string) {
		t.Helper()
		c, r := e.js("POST", "/api/nodes/"+fileID+"/share-links", e.admin, body)
		if c != 201 {
			t.Fatalf("201 bekleniyordu: %d %v", c, r)
		}
		tok := str(r, "token")
		allTokens = append(allTokens, tok)
		return str(r, "id"), tok
	}
	get := func(tok string) (*http.Response, []byte) {
		return e.do("GET", "/api/s/"+tok+"/download", "", nil, "")
	}
	post := func(tok, pw string) (*http.Response, []byte) {
		b, _ := json.Marshal(map[string]string{"password": pw})
		return e.do("POST", "/api/s/"+tok+"/download", "", bytes.NewReader(b), "application/json")
	}
	var firstToken string

	t.Run("token yalnızca hash olarak saklanır", func(t *testing.T) {
		id, tok := mustCreate(map[string]any{"expires_in_seconds": 3600})
		firstToken = tok
		if len(tok) != 43 {
			t.Fatalf("43 karakterlik token bekleniyordu, gelen %d", len(tok))
		}
		if n := e.count(`SELECT count(*) FROM share_links WHERE id = $1::uuid AND token_hash = $2`, id, tokenHash(tok)); n != 1 {
			t.Fatalf("hash eşleşmesi bekleniyordu, gelen %d", n)
		}
		if n := e.count(`SELECT count(*) FROM share_links WHERE token_hash = $1`, tok); n != 0 {
			t.Fatal("ham token veritabanında saklanmamalı")
		}
		resp, body := e.do("GET", "/api/nodes/"+fileID+"/share-links", e.admin, nil, "")
		if resp.StatusCode != 200 || strings.Contains(string(body), tok) {
			t.Fatalf("liste token içermemeli: %d", resp.StatusCode)
		}
	})

	t.Run("parolasız bağlantıyla indirme", func(t *testing.T) {
		_, tok := mustCreate(map[string]any{"expires_in_seconds": 3600})
		resp, body := e.do("GET", "/api/s/"+tok, "", nil, "")
		if resp.StatusCode != 200 || decode(body)["requires_password"] != false {
			t.Fatalf("bilgi ucu beklenmedik: %d %s", resp.StatusCode, body)
		}
		resp, body = get(tok)
		if resp.StatusCode != 200 || !bytes.Equal(body, content) {
			t.Fatalf("indirme başarısız: %d %q", resp.StatusCode, body)
		}
		if resp.Header.Get("X-Content-Type-Options") != "nosniff" ||
			!strings.HasPrefix(resp.Header.Get("Content-Disposition"), "attachment") {
			t.Fatal("güvenlik başlıkları eksik")
		}
	})

	t.Run("indirme sayısı sınırı", func(t *testing.T) {
		_, tok := mustCreate(map[string]any{"expires_in_seconds": 3600, "max_downloads": 2})
		for i := 0; i < 2; i++ {
			if resp, _ := get(tok); resp.StatusCode != 200 {
				t.Fatalf("%d. indirme 200 olmalı: %d", i+1, resp.StatusCode)
			}
		}
		if resp, _ := get(tok); resp.StatusCode != 410 {
			t.Fatalf("3. indirme 410 olmalı: %d", resp.StatusCode)
		}
	})

	t.Run("eşzamanlı indirmede sınır aşılmaz", func(t *testing.T) {
		id, tok := mustCreate(map[string]any{"expires_in_seconds": 3600, "max_downloads": 3})
		var okN, goneN int32
		var wg sync.WaitGroup
		for i := 0; i < 20; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				resp, err := http.Get(e.srv.URL + "/api/s/" + tok + "/download")
				if err != nil {
					t.Error(err)
					return
				}
				defer func() {
					if err := resp.Body.Close(); err != nil {
						t.Errorf("response body kapatılamadı: %v", err)
					}
				}()
				_, _ = io.Copy(io.Discard, resp.Body)
				switch resp.StatusCode {
				case 200:
					atomic.AddInt32(&okN, 1)
				case 410:
					atomic.AddInt32(&goneN, 1)
				default:
					t.Errorf("beklenmeyen durum: %d", resp.StatusCode)
				}
			}()
		}
		wg.Wait()
		if okN != 3 || goneN != 17 {
			t.Fatalf("3 başarılı ve 17 reddedilen bekleniyordu: %d / %d", okN, goneN)
		}
		if n := e.count(`SELECT download_count FROM share_links WHERE id = $1::uuid`, id); n != 3 {
			t.Fatalf("download_count 3 olmalı, gelen %d", n)
		}
	})

	t.Run("parola korumalı bağlantı", func(t *testing.T) {
		_, tok := mustCreate(map[string]any{"expires_in_seconds": 3600, "password": "Sifre-12345"})
		if resp, _ := get(tok); resp.StatusCode != 401 {
			t.Fatalf("parolasız GET 401 olmalı: %d", resp.StatusCode)
		}
		if resp, _ := post(tok, "yanlis-parola"); resp.StatusCode != 401 {
			t.Fatalf("yanlış parola 401 olmalı: %d", resp.StatusCode)
		}
		resp, body := post(tok, "Sifre-12345")
		if resp.StatusCode != 200 || !bytes.Equal(body, content) {
			t.Fatalf("doğru parola 200 olmalı: %d", resp.StatusCode)
		}
	})

	t.Run("brute-force denemeleri kilitlenir", func(t *testing.T) {
		_, tok := mustCreate(map[string]any{"expires_in_seconds": 3600, "password": "Dogru-Parola-1"})
		for i := 0; i < 5; i++ {
			if resp, _ := post(tok, fmt.Sprintf("yanlis-%d", i)); resp.StatusCode != 401 {
				t.Fatalf("%d. deneme 401 olmalı: %d", i+1, resp.StatusCode)
			}
		}
		resp, _ := post(tok, "yanlis-son")
		if resp.StatusCode != 429 || resp.Header.Get("Retry-After") == "" {
			t.Fatalf("429 ve Retry-After bekleniyordu: %d %q", resp.StatusCode, resp.Header.Get("Retry-After"))
		}
		if resp, _ := post(tok, "Dogru-Parola-1"); resp.StatusCode != 429 {
			t.Fatalf("kilitliyken doğru parola da 429 olmalı: %d", resp.StatusCode)
		}
	})

	t.Run("süre dolunca erişim kapanır", func(t *testing.T) {
		id, tok := mustCreate(map[string]any{"expires_in_seconds": 3600})
		if _, err := e.pool.Exec(context.Background(),
			`UPDATE share_links SET expires_at = now() - interval '1 minute' WHERE id = $1::uuid`, id); err != nil {
			t.Fatal(err)
		}
		if resp, _ := get(tok); resp.StatusCode != 410 {
			t.Fatalf("410 bekleniyordu: %d", resp.StatusCode)
		}
	})

	t.Run("iptal edilen bağlantı çalışmaz", func(t *testing.T) {
		id, tok := mustCreate(map[string]any{"expires_in_seconds": 3600})
		if c, _ := e.js("DELETE", "/api/share-links/"+id, e.emp, nil); c != 403 {
			t.Fatalf("yetkisiz iptal 403 olmalı: %d", c)
		}
		if c, _ := e.js("DELETE", "/api/share-links/"+id, e.admin, nil); c != 204 {
			t.Fatalf("iptal 204 olmalı: %d", c)
		}
		if c, _ := e.js("DELETE", "/api/share-links/"+id, e.admin, nil); c != 204 {
			t.Fatalf("tekrar iptal 204 olmalı: %d", c)
		}
		if resp, _ := get(tok); resp.StatusCode != 410 {
			t.Fatalf("iptalden sonra 410 bekleniyordu: %d", resp.StatusCode)
		}
	})

	t.Run("bilinmeyen veya bozuk token 404", func(t *testing.T) {
		if resp, _ := get(strings.Repeat("A", 43)); resp.StatusCode != 404 {
			t.Fatalf("404 bekleniyordu: %d", resp.StatusCode)
		}
		if resp, _ := get("kisa"); resp.StatusCode != 404 {
			t.Fatalf("404 bekleniyordu: %d", resp.StatusCode)
		}
	})

	t.Run("paylaşım yetkisi olmayan bağlantı oluşturamaz", func(t *testing.T) {
		c, _ := e.js("POST", "/api/nodes/"+fileID+"/share-links", e.emp, map[string]any{"expires_in_seconds": 3600})
		if c != 403 {
			t.Fatalf("403 bekleniyordu: %d", c)
		}
	})

	t.Run("geçersiz parametreler reddedilir", func(t *testing.T) {
		for _, body := range []map[string]any{
			{"expires_in_seconds": 10},
			{"expires_in_seconds": 99999999},
			{"expires_in_seconds": 3600, "max_downloads": 0},
			{"expires_in_seconds": 3600, "password": "kisa"},
		} {
			if c, _ := e.js("POST", "/api/nodes/"+fileID+"/share-links", e.admin, body); c != 400 {
				t.Fatalf("400 bekleniyordu (%v): %d", body, c)
			}
		}
	})

	t.Run("oluşturan okuma yetkisini kaybedince bağlantı kapanır", func(t *testing.T) {
		grant := func(perm string) string {
			c, r := e.js("POST", "/api/nodes/"+fileID+"/acl", e.admin, map[string]any{
				"subject_type": "user", "subject_id": e.empID, "permission": perm, "effect": "allow"})
			if c != 200 {
				t.Fatalf("yetki verilemedi: %d %v", c, r)
			}
			return str(r, "id")
		}
		readEntry := grant("read")
		grant("share")
		c, r := e.js("POST", "/api/nodes/"+fileID+"/share-links", e.emp, map[string]any{"expires_in_seconds": 3600})
		if c != 201 {
			t.Fatalf("çalışan bağlantı oluşturabilmeli: %d %v", c, r)
		}
		tok := str(r, "token")
		allTokens = append(allTokens, tok)
		if resp, _ := get(tok); resp.StatusCode != 200 {
			t.Fatalf("başlangıçta 200 bekleniyordu: %d", resp.StatusCode)
		}
		if c, _ := e.js("DELETE", "/api/nodes/"+fileID+"/acl/"+readEntry, e.admin, nil); c != 204 {
			t.Fatalf("yetki kaldırılamadı: %d", c)
		}
		if resp, _ := get(tok); resp.StatusCode != 410 {
			t.Fatalf("yetki kalkınca 410 bekleniyordu: %d", resp.StatusCode)
		}
	})

	t.Run("her erişim denetim zincirinde, sırlar hiçbir yerde yok", func(t *testing.T) {
		for action, min := range map[string]int{
			"share.created": 5, "share.download": 3, "share.denied": 3, "share.revoked": 1, "share.view": 1,
		} {
			if n := e.count(`SELECT count(*) FROM audit_log WHERE action = $1`, action); n < min {
				t.Fatalf("%s için en az %d kayıt bekleniyordu, gelen %d", action, min, n)
			}
		}
		secrets := append([]string{"Sifre-12345", "Dogru-Parola-1"}, allTokens...)
		for _, s := range secrets {
			n := e.count(`SELECT count(*) FROM audit_log
WHERE position($1 in new_value) > 0 OR position($1 in old_value) > 0
   OR position($1 in target_id) > 0 OR position($1 in actor_id) > 0`, s)
			if n != 0 {
				t.Fatalf("sır denetim kaydında bulundu: %q", s)
			}
		}
		if firstToken == "" {
			t.Fatal("ilk token kaydedilmemiş")
		}
		res, err := audit.New(e.pool).Verify(context.Background())
		if err != nil || !res.Valid {
			t.Fatalf("zincir geçerli olmalı: %+v %v", res, err)
		}
	})
}
