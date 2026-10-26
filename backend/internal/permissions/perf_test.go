package permissions

import (
	"context"
	"fmt"
	"os"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/yoruware/ddo-case-betul-sakrak/backend/internal/testutil"
)

func percentile(sorted []time.Duration, p float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	return sorted[int(float64(len(sorted)-1)*p)]
}

func summarize(name string, lat []time.Duration) time.Duration {
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })

	p95 := percentile(lat, 0.95)
	fmt.Printf(
		"%s: n=%d p50=%v p95=%v p99=%v max=%v\n",
		name,
		len(lat),
		percentile(lat, 0.50),
		p95,
		percentile(lat, 0.99),
		lat[len(lat)-1],
	)

	return p95
}

func TestPerfEtkinYetki100kDugum(t *testing.T) {
	if os.Getenv("PERF") == "" {
		t.Skip("ölçüm için PERF=1 ayarla")
	}

	ctx := context.Background()
	pool := testutil.NewPool(t)
	svc := New(pool)

	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("SQL başarısız:\n%s\nHata: %v", sql, err)
		}
	}

	// Test kullanıcıları ve grup.
	var admin, user, group string

	if err := pool.QueryRow(ctx, `
		INSERT INTO users (email, password_hash, full_name, role)
		VALUES ('admin@perf', 'x', 'a', 'admin')
		RETURNING id::text`,
	).Scan(&admin); err != nil {
		t.Fatal(err)
	}

	if err := pool.QueryRow(ctx, `
		INSERT INTO users (email, password_hash, full_name, role)
		VALUES ('user@perf', 'x', 'u', 'employee')
		RETURNING id::text`,
	).Scan(&user); err != nil {
		t.Fatal(err)
	}

	if err := pool.QueryRow(ctx, `
		INSERT INTO groups (name)
		VALUES ('perf-grup')
		RETURNING id::text`,
	).Scan(&group); err != nil {
		t.Fatal(err)
	}

	exec(
		`INSERT INTO group_members (group_id, user_id)
		 VALUES ($1::uuid, $2::uuid)`,
		group,
		user,
	)

	// 10.000 zincir x 10 seviye = 100.000 düğüm.
	start := time.Now()

	exec(`
		WITH ids AS MATERIALIZED (
			SELECT lvl, j, gen_random_uuid() AS id
			FROM generate_series(1, 10) lvl,
			     generate_series(1, 10000) j
		)
		INSERT INTO nodes (
			id, parent_id, kind, name, owner_id, ancestor_ids
		)
		SELECT
			id,
			lag(id) OVER w,
			'folder',
			'n-' || lvl || '-' || j,
			$1::uuid,
			array_agg(id) OVER w
		FROM ids
		WINDOW w AS (PARTITION BY j ORDER BY lvl)`,
		admin,
	)

	// Grup: kök klasörlerde read allow.
	exec(`
		INSERT INTO acl_entries (
			node_id, subject_type, subject_id,
			permission, effect, created_by
		)
		SELECT
			id, 'group', $1::uuid,
			'read', 'allow', $2::uuid
		FROM nodes
		WHERE parent_id IS NULL
		LIMIT 5000`,
		group,
		admin,
	)

	// Kullanıcı: altıncı seviyedeki klasörlerde read deny.
	exec(`
		INSERT INTO acl_entries (
			node_id, subject_type, subject_id,
			permission, effect, created_by
		)
		SELECT
			id, 'user', $1::uuid,
			'read', 'deny', $2::uuid
		FROM nodes
		WHERE cardinality(ancestor_ids) = 6
		ORDER BY random()
		LIMIT 500`,
		user,
		admin,
	)

	// Gürültü: başka kullanıcılara ait 50.000 kayıt.
	exec(`
		INSERT INTO acl_entries (
			node_id, subject_type, subject_id,
			permission, effect, created_by
		)
		SELECT
			id, 'user', gen_random_uuid(),
			'read', 'allow', $1::uuid
		FROM nodes
		ORDER BY random()
		LIMIT 50000`,
		admin,
	)

	exec(`ANALYZE nodes`)
	exec(`ANALYZE acl_entries`)

	var nNodes, nACL int

	if err := pool.QueryRow(ctx, `SELECT count(*) FROM nodes`).Scan(&nNodes); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM acl_entries`).Scan(&nACL); err != nil {
		t.Fatal(err)
	}

	fmt.Printf(
		"veri hazır (%v): %d düğüm, %d yetki kaydı, derinlik 10\n",
		time.Since(start).Round(time.Millisecond),
		nNodes,
		nACL,
	)

	// Ölçüm için 3.000 yaprak düğüm seç.
	rows, err := pool.Query(ctx, `
		SELECT id::text
		FROM nodes
		WHERE cardinality(ancestor_ids) = 10
		ORDER BY random()
		LIMIT 3000`)
	if err != nil {
		t.Fatal(err)
	}

	var leaves []string

	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		leaves = append(leaves, id)
	}

	if err := rows.Err(); err != nil {
		rows.Close()
		t.Fatal(err)
	}
	rows.Close()

	if len(leaves) == 0 {
		t.Fatal("ölçüm için yaprak düğüm bulunamadı")
	}

	// Isınma.
	for i := 0; i < 200; i++ {
		if _, err := svc.Check(ctx, user, leaves[i%len(leaves)], Read); err != nil {
			t.Fatal(err)
		}
	}

	// 1. Sıralı ölçüm.
	seq := make([]time.Duration, 0, len(leaves))
	allowed := 0

	for _, id := range leaves {
		st := time.Now()

		ok, err := svc.Check(ctx, user, id, Read)
		if err != nil {
			t.Fatal(err)
		}

		seq = append(seq, time.Since(st))
		if ok {
			allowed++
		}
	}

	fmt.Printf(
		"sonuç dağılımı: %d izinli, %d reddedilen\n",
		allowed,
		len(leaves)-allowed,
	)

	p95seq := summarize("sıralı (1 istemci)", seq)

	// 2. Eşzamanlı ölçüm: 8 istemci x 500 istek.
	const workers, per = 8, 500

	lats := make([][]time.Duration, workers)
	var wg sync.WaitGroup

	for w := 0; w < workers; w++ {
		wg.Add(1)

		go func(w int) {
			defer wg.Done()

			for i := 0; i < per; i++ {
				id := leaves[(w*per+i)%len(leaves)]
				st := time.Now()

				if _, err := svc.Check(ctx, user, id, Read); err != nil {
					t.Errorf("eşzamanlı yetki kontrolü: %v", err)
					return
				}

				lats[w] = append(lats[w], time.Since(st))
			}
		}(w)
	}

	wg.Wait()

	var all []time.Duration
	for _, l := range lats {
		all = append(all, l...)
	}

	p95par := summarize("eşzamanlı (8 istemci)", all)

	// Yardımcı: aynı sorguyla EXPLAIN ANALYZE çıktısını yazdır.
	explain := func(label, nodeID string) {
		t.Helper()

		er, err := pool.Query(
			ctx,
			"EXPLAIN (ANALYZE, BUFFERS) "+rulesSQL,
			nodeID,
			user,
		)
		if err != nil {
			t.Fatal(err)
		}
		defer er.Close()

		fmt.Printf("--- %s ---\n", label)

		for er.Next() {
			var line string
			if err := er.Scan(&line); err != nil {
				t.Fatal(err)
			}
			fmt.Println(line)
		}

		if err := er.Err(); err != nil {
			t.Fatal(err)
		}
	}

	// 3. İndeksler açıkken referans ölçümü.
	const compareCount = 1000

	measureChecks := func(name string) []time.Duration {
		t.Helper()

		latencies := make([]time.Duration, 0, compareCount)

		for i := 0; i < compareCount; i++ {
			id := leaves[i%len(leaves)]
			st := time.Now()

			if _, err := svc.Check(ctx, user, id, Read); err != nil {
				t.Fatalf("%s ölçümü başarısız: %v", name, err)
			}

			latencies = append(latencies, time.Since(st))
		}

		summarize(name, latencies)
		return latencies
	}

	indexedLatencies := measureChecks("ACL indeksleri AÇIK")
	explain("ACL indeksleri AÇIK: EXPLAIN", leaves[0])

	// 4. Yetki kayıtlarını node_id ile arayan indeksleri kaldır.
	//
	// ÖNEMLİ:
	// Bu işlem yalnızca testutil.NewPool(t) tarafından oluşturulan
	// geçici test veritabanında yapılmalıdır.
	//
	// Bileşik indeks UNIQUE constraint tarafından oluşturulduğu için
	// önce constraint kaldırılır. Böylece onun indeksinin de
	// silinmesi sağlanır.
	exec(`DROP INDEX idx_acl_node`)

	exec(`
		ALTER TABLE acl_entries
		DROP CONSTRAINT acl_entries_node_id_subject_type_subject_id_permission_key
	`)

	exec(`ANALYZE acl_entries`)

	// İndeksler kaldırıldıktan sonra aynı düğümlerle ölç.
	noIndexLatencies := measureChecks("ACL indeksleri KAPALI")
	explain("ACL indeksleri KAPALI: EXPLAIN", leaves[0])

	p95Indexed := percentile(indexedLatencies, 0.95)
	p95NoIndex := percentile(noIndexLatencies, 0.95)

	fmt.Printf(
		"ACL indeksleri karşılaştırması: p95 açık=%v, kapalı=%v\n",
		p95Indexed,
		p95NoIndex,
	)

	if p95Indexed > 0 {
		fmt.Printf(
			"p95 oranı (kapalı/açık): %.2fx\n",
			float64(p95NoIndex)/float64(p95Indexed),
		)
	}

	// 5. İndeksleri ve UNIQUE constraint'i geri oluştur.
	// Test veritabanı geçici olsa da testin kalan kısmında şemayı
	// orijinal durumuna döndürmek daha temizdir.
	exec(`
		ALTER TABLE acl_entries
		ADD CONSTRAINT acl_entries_node_id_subject_type_subject_id_permission_key
		UNIQUE (node_id, subject_type, subject_id, permission)
	`)

	exec(`CREATE INDEX idx_acl_node ON acl_entries (node_id)`)
	exec(`ANALYZE acl_entries`)

	// 6. İndeksler geri geldikten sonra son planı da kaydet.
	explain("İndeksler geri yüklendi: EXPLAIN", leaves[0])

	if p95seq >= 30*time.Millisecond || p95par >= 30*time.Millisecond {
		t.Fatalf(
			"p95 hedefi aşıldı: sıralı=%v eşzamanlı=%v (hedef < 30ms)",
			p95seq,
			p95par,
		)
	}
}
