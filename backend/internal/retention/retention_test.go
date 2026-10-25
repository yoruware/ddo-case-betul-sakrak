package retention_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yoruware/ddo-case-betul-sakrak/backend/internal/audit"
	"github.com/yoruware/ddo-case-betul-sakrak/backend/internal/retention"
	"github.com/yoruware/ddo-case-betul-sakrak/backend/internal/storage"
	"github.com/yoruware/ddo-case-betul-sakrak/backend/internal/testutil"
)

var ctx = context.Background()

type fx struct {
	t     *testing.T
	pool  *pgxpool.Pool
	store *storage.Store
	dir   string
	svc   *retention.Service
	aud   *audit.Service
	owner string
}

func newFx(t *testing.T) *fx {
	t.Helper()
	pool := testutil.NewPool(t)
	dir := t.TempDir()
	store, err := storage.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	aud := audit.New(pool)
	f := &fx{t: t, pool: pool, store: store, dir: dir, aud: aud, svc: retention.New(pool, aud, store)}
	err = pool.QueryRow(ctx, `INSERT INTO users (email, password_hash, full_name, role)
		VALUES ('owner@test','x','owner','admin') RETURNING id::text`).Scan(&f.owner)
	if err != nil {
		t.Fatal(err)
	}
	f.exec(`INSERT INTO document_types (code, name, retention_days) VALUES ('anlik','Anında',0), ('uzun','Uzun',3650)`)
	return f
}

func (f *fx) exec(q string, args ...any) {
	f.t.Helper()
	if _, err := f.pool.Exec(ctx, q, args...); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fx) count(q string, args ...any) int {
	f.t.Helper()
	var n int
	if err := f.pool.QueryRow(ctx, q, args...).Scan(&n); err != nil {
		f.t.Fatal(err)
	}
	return n
}

func (f *fx) node(kind string, parent *string, name string) string {
	f.t.Helper()
	var id string
	err := f.pool.QueryRow(ctx, `
WITH nid AS (SELECT gen_random_uuid() AS id)
INSERT INTO nodes (id, parent_id, kind, name, owner_id, ancestor_ids)
SELECT nid.id, $1::uuid, $2::text, $3::text, $4::uuid,
       array_append(COALESCE((SELECT ancestor_ids FROM nodes WHERE id = $1::uuid), '{}'::uuid[]), nid.id)
FROM nid RETURNING id::text`, parent, kind, name, f.owner).Scan(&id)
	if err != nil {
		f.t.Fatal(err)
	}
	return id
}

func shaOf(content []byte) string {
	s := sha256.Sum256(content)
	return hex.EncodeToString(s[:])
}

func (f *fx) file(parent *string, name string, content []byte) string {
	f.t.Helper()
	id := f.node("file", parent, name)
	sha := shaOf(content)
	if !f.store.Exists(sha) {
		tmp, err := f.store.NewTemp()
		if err != nil {
			f.t.Fatal(err)
		}
		if _, err := tmp.Write(content); err != nil {
			f.t.Fatal(err)
		}
		_ = tmp.Close()
		if _, err := f.store.Commit(tmp.Name(), sha); err != nil {
			f.t.Fatal(err)
		}
	}
	f.exec(`INSERT INTO blobs (sha256, size_bytes) VALUES ($1, $2) ON CONFLICT (sha256) DO NOTHING`, sha, len(content))
	f.exec(`INSERT INTO file_versions (node_id, version_no, sha256, size_bytes, mime_type, original_name, uploaded_by)
		VALUES ($1::uuid, 1, $2, $3, 'text/plain', $4, $5::uuid)`, id, sha, len(content), name, f.owner)
	return id
}

func (f *fx) blobOnDisk(content []byte) bool {
	sha := shaOf(content)
	_, err := os.Stat(filepath.Join(f.dir, "blobs", sha[:2], sha))
	return err == nil
}

func (f *fx) destroyed(id string) bool {
	return f.count(`SELECT count(*) FROM nodes WHERE id = $1::uuid AND destroyed_at IS NOT NULL`, id) == 1
}

func (f *fx) assign(id, docType string) {
	f.t.Helper()
	if _, err := f.svc.AssignRetention(ctx, f.owner, id, docType); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fx) run() retention.RunResult {
	f.t.Helper()
	r, err := f.svc.Run(ctx, f.owner, 500)
	if err != nil {
		f.t.Fatal(err)
	}
	return r
}

func (f *fx) certOf(node string) string {
	f.t.Helper()
	var id string
	if err := f.pool.QueryRow(ctx, `SELECT id::text FROM destruction_certificates WHERE node_id = $1::uuid`, node).Scan(&id); err != nil {
		f.t.Fatal(err)
	}
	return id
}

func TestSaklamaVeImha(t *testing.T) {
	f := newFx(t)
	var sampleCert string

	t.Run("saklama kaydı atama kuralları", func(t *testing.T) {
		folder := f.node("folder", nil, "klasor")
		if _, err := f.svc.AssignRetention(ctx, f.owner, folder, "uzun"); !errors.Is(err, retention.ErrNotFile) {
			t.Fatalf("ErrNotFile bekleniyordu: %v", err)
		}
		file := f.file(nil, "uzun-sureli.txt", []byte("uzun sureli icerik"))
		if _, err := f.svc.AssignRetention(ctx, f.owner, file, "yok"); !errors.Is(err, retention.ErrUnknownDocType) {
			t.Fatalf("ErrUnknownDocType bekleniyordu: %v", err)
		}
		until, err := f.svc.AssignRetention(ctx, f.owner, file, "uzun")
		if err != nil {
			t.Fatal(err)
		}
		if !until.After(time.Now().AddDate(9, 0, 0)) {
			t.Fatalf("saklama bitişi yaklaşık 10 yıl sonra olmalı: %v", until)
		}
		if _, err := f.svc.AssignRetention(ctx, f.owner, file, "anlik"); !errors.Is(err, retention.ErrAlreadyAssigned) {
			t.Fatalf("ErrAlreadyAssigned bekleniyordu: %v", err)
		}
		var ghost string
		if err := f.pool.QueryRow(ctx, `SELECT gen_random_uuid()::text`).Scan(&ghost); err != nil {
			t.Fatal(err)
		}
		if _, err := f.svc.AssignRetention(ctx, f.owner, ghost, "uzun"); !errors.Is(err, retention.ErrNotFound) {
			t.Fatalf("ErrNotFound bekleniyordu: %v", err)
		}
		f.run()
		if f.destroyed(file) {
			t.Fatal("süresi dolmamış belge imha edilmemeli")
		}
	})

	var drained string
	t.Run("süresi dolan belge imha edilir ve tutanak üretilir", func(t *testing.T) {
		content := []byte("imha edilecek gizli icerik")
		id := f.file(nil, "eski.txt", content)
		drained = id
		f.assign(id, "anlik")
		f.exec(`INSERT INTO share_links (node_id, token_hash, expires_at, created_by)
			VALUES ($1::uuid, repeat('a', 64), now() + interval '1 hour', $2::uuid)`, id, f.owner)

		res := f.run()
		if res.Destroyed < 1 {
			t.Fatalf("en az 1 imha bekleniyordu: %+v", res)
		}
		if !f.destroyed(id) {
			t.Fatal("düğüm imha edilmiş görünmeli")
		}
		if n := f.count(`SELECT count(*) FROM file_versions WHERE node_id = $1::uuid`, id); n != 0 {
			t.Fatalf("sürümler silinmeli, kalan %d", n)
		}
		if n := f.count(`SELECT count(*) FROM blobs WHERE sha256 = $1`, shaOf(content)); n != 0 {
			t.Fatalf("blob kaydı silinmeli, kalan %d", n)
		}
		if f.blobOnDisk(content) {
			t.Fatal("blob dosyası diskten silinmeli")
		}
		if n := f.count(`SELECT count(*) FROM share_links WHERE node_id = $1::uuid AND revoked_at IS NOT NULL`, id); n != 1 {
			t.Fatalf("paylaşım bağlantısı iptal edilmeli, iptal edilen %d", n)
		}
		sampleCert = f.certOf(id)
		view, err := f.svc.GetCertificate(ctx, sampleCert)
		if err != nil || !view.Verification.Valid {
			t.Fatalf("tutanak geçerli olmalı: %+v %v", view, err)
		}
		if !strings.Contains(string(view.Body), shaOf(content)) {
			t.Fatal("tutanak içerik hash'ini taşımalı")
		}
		if files, _ := os.ReadDir(filepath.Join(f.dir, "trash")); len(files) != 0 {
			t.Fatalf("çöp klasörü boş olmalı, kalan %d", len(files))
		}
	})

	t.Run("imha idempotent: tekrar çalıştırmak hiçbir şeyi değiştirmez", func(t *testing.T) {
		auditBefore := f.count(`SELECT count(*) FROM audit_log`)
		certsBefore := f.count(`SELECT count(*) FROM destruction_certificates`)
		res := f.run()
		if res.Checked != 0 || res.Destroyed != 0 {
			t.Fatalf("tekrar çalıştırma boş olmalı: %+v", res)
		}
		if f.count(`SELECT count(*) FROM audit_log`) != auditBefore ||
			f.count(`SELECT count(*) FROM destruction_certificates`) != certsBefore {
			t.Fatal("tekrar çalıştırma yeni kayıt üretmemeli")
		}
		if n := f.count(`SELECT count(*) FROM audit_log WHERE action = 'retention.destroyed' AND target_id = $1`, drained); n != 1 {
			t.Fatalf("tek imha kaydı bekleniyordu, gelen %d", n)
		}
	})

	t.Run("hukuki bekletme imhayı engeller", func(t *testing.T) {
		content := []byte("dava delili")
		folder := f.node("folder", nil, "Dava")
		file := f.file(&folder, "delil.txt", content)
		f.assign(file, "anlik")
		holdID, err := f.svc.PlaceHold(ctx, f.owner, folder, "DAVA-2026-1", "test")
		if err != nil {
			t.Fatal(err)
		}
		if res := f.run(); res.BlockedByHold < 1 {
			t.Fatalf("en az 1 engellenen bekleniyordu: %+v", res)
		}
		if f.destroyed(file) || f.count(`SELECT count(*) FROM file_versions WHERE node_id = $1::uuid`, file) != 1 || !f.blobOnDisk(content) {
			t.Fatal("bekletme altındaki belge dokunulmamış olmalı")
		}
		f.run()
		if n := f.count(`SELECT count(*) FROM audit_log WHERE action = 'retention.blocked_by_hold' AND target_id = $1`, file); n != 1 {
			t.Fatalf("engelleme bir kez kaydedilmeli, gelen %d", n)
		}
		if ok, err := f.svc.ReleaseHold(ctx, f.owner, holdID); err != nil || !ok {
			t.Fatalf("kaldırma başarılı olmalı: %v %v", ok, err)
		}
		if ok, err := f.svc.ReleaseHold(ctx, f.owner, holdID); err != nil || ok {
			t.Fatalf("ikinci kaldırma (false, nil) dönmeli: %v %v", ok, err)
		}
		var ghost string
		if err := f.pool.QueryRow(ctx, `SELECT gen_random_uuid()::text`).Scan(&ghost); err != nil {
			t.Fatal(err)
		}
		if _, err := f.svc.ReleaseHold(ctx, f.owner, ghost); !errors.Is(err, retention.ErrNotFound) {
			t.Fatalf("ErrNotFound bekleniyordu: %v", err)
		}
		f.run()
		if !f.destroyed(file) {
			t.Fatal("bekletme kalkınca belge imha edilmeli")
		}
		if _, err := f.svc.PlaceHold(ctx, f.owner, file, "X", ""); !errors.Is(err, retention.ErrDestroyed) {
			t.Fatalf("ErrDestroyed bekleniyordu: %v", err)
		}
	})

	t.Run("ortak blob son kullanıcı imha edilene kadar korunur", func(t *testing.T) {
		content := []byte("ortak icerik")
		a := f.file(nil, "ortak-a.txt", content)
		b := f.file(nil, "ortak-b.txt", content)
		f.assign(a, "anlik")
		f.run()
		if !f.destroyed(a) {
			t.Fatal("a imha edilmeli")
		}
		if !f.blobOnDisk(content) || f.count(`SELECT count(*) FROM blobs WHERE sha256 = $1`, shaOf(content)) != 1 {
			t.Fatal("blob b için korunmalı")
		}
		if f.count(`SELECT count(*) FROM file_versions WHERE node_id = $1::uuid`, b) != 1 {
			t.Fatal("b'nin sürümü korunmalı")
		}
		view, err := f.svc.GetCertificate(ctx, f.certOf(a))
		if err != nil || !strings.Contains(string(view.Body), `"shared_blob":true`) {
			t.Fatalf("tutanak ortak blobu belirtmeli: %v", err)
		}
		f.assign(b, "anlik")
		f.run()
		if !f.destroyed(b) || f.blobOnDisk(content) || f.count(`SELECT count(*) FROM blobs WHERE sha256 = $1`, shaOf(content)) != 0 {
			t.Fatal("son kullanıcı imha edilince blob da silinmeli")
		}
	})

	t.Run("eşzamanlı çalıştırmalar her belgeyi tam bir kez imha eder", func(t *testing.T) {
		var ids []string
		for i := 0; i < 10; i++ {
			id := f.file(nil, "es-"+string(rune('a'+i))+".txt", []byte("eszamanli icerik "+string(rune('a'+i))))
			f.assign(id, "anlik")
			ids = append(ids, id)
		}
		var wg sync.WaitGroup
		results := make([]retention.RunResult, 3)
		for i := range results {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				r, err := f.svc.Run(ctx, f.owner, 500)
				if err != nil {
					t.Error(err)
				}
				results[i] = r
			}(i)
		}
		wg.Wait()
		for _, r := range results {
			if r.Failed != 0 {
				t.Fatalf("hata beklenmiyordu: %+v", r)
			}
		}
		for _, id := range ids {
			if !f.destroyed(id) {
				t.Fatalf("imha edilmeliydi: %s", id)
			}
			if n := f.count(`SELECT count(*) FROM destruction_certificates WHERE node_id = $1::uuid`, id); n != 1 {
				t.Fatalf("tek tutanak bekleniyordu, gelen %d", n)
			}
			if n := f.count(`SELECT count(*) FROM audit_log WHERE action = 'retention.destroyed' AND target_id = $1`, id); n != 1 {
				t.Fatalf("tek imha kaydı bekleniyordu, gelen %d", n)
			}
		}
	})

	t.Run("denetim zinciri sağlam", func(t *testing.T) {
		res, err := f.aud.Verify(ctx)
		if err != nil || !res.Valid {
			t.Fatalf("zincir geçerli olmalı: %+v %v", res, err)
		}
	})

	t.Run("tutanak kurcalanması fark edilir", func(t *testing.T) {
		f.exec(`UPDATE destruction_certificates SET body = body || ' ' WHERE id = $1::uuid`, sampleCert)
		view, err := f.svc.GetCertificate(ctx, sampleCert)
		if err != nil {
			t.Fatal(err)
		}
		if view.Verification.BodyHashValid || view.Verification.Valid {
			t.Fatalf("kurcalanmış tutanak geçersiz görünmeli: %+v", view.Verification)
		}
	})
}