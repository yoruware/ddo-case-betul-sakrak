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
	fmt.Printf("%s: n=%d p50=%v p95=%v p99=%v max=%v\n",
		name, len(lat), percentile(lat, 0.50), p95, percentile(lat, 0.99), lat[len(lat)-1])
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
			t.Fatal(err)
		}
	}

	var admin, user, group string
	if err := pool.QueryRow(ctx, `INSERT INTO users (email,password_hash,full_name,role)
		VALUES ('admin@perf','x','a','admin') RETURNING id::text`).Scan(&admin); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO users (email,password_hash,full_name,role)
		VALUES ('user@perf','x','u','employee') RETURNING id::text`).Scan(&user); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO groups (name) VALUES ('perf-grup') RETURNING id::text`).Scan(&group); err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO group_members (group_id, user_id) VALUES ($1::uuid, $2::uuid)`, group, user)

	// 10.000 zincir x 10 seviye = 100.000 düğüm. ancestor_ids pencere fonksiyonuyla üretilir.
	start := time.Now()
	exec(`
WITH ids AS MATERIALIZED (
  SELECT lvl, j, gen_random_uuid() AS id
  FROM generate_series(1,10) lvl, generate_series(1,10000) j
)
INSERT INTO nodes (id, parent_id, kind, name, owner_id, ancestor_ids)
SELECT id, lag(id) OVER w, 'folder', 'n-' || lvl || '-' || j, $1::uuid, array_agg(id) OVER w
FROM ids
WINDOW w AS (PARTITION BY j ORDER BY lvl)`, admin)

	// Grup, 5.000 kök klasörde read allow; kullanıcı, 500 altıncı seviye klasörde read deny.
	exec(`INSERT INTO acl_entries (node_id, subject_type, subject_id, permission, effect, created_by)
		SELECT id, 'group', $1::uuid, 'read', 'allow', $2::uuid
		FROM nodes WHERE parent_id IS NULL LIMIT 5000`, group, admin)
	exec(`INSERT INTO acl_entries (node_id, subject_type, subject_id, permission, effect, created_by)
		SELECT id, 'user', $1::uuid, 'read', 'deny', $2::uuid
		FROM nodes WHERE cardinality(ancestor_ids) = 6 ORDER BY random() LIMIT 500`, user, admin)
	// Gürültü: başka öznelere ait 50.000 kayıt.
	exec(`INSERT INTO acl_entries (node_id, subject_type, subject_id, permission, effect, created_by)
		SELECT id, 'user', gen_random_uuid(), 'read', 'allow', $1::uuid
		FROM nodes ORDER BY random() LIMIT 50000`, admin)
	exec(`ANALYZE nodes`)
	exec(`ANALYZE acl_entries`)

	var nNodes, nACL int
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM nodes`).Scan(&nNodes)
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM acl_entries`).Scan(&nACL)
	fmt.Printf("veri hazır (%v): %d düğüm, %d yetki kaydı, derinlik 10\n",
		time.Since(start).Round(time.Millisecond), nNodes, nACL)

	rows, err := pool.Query(ctx, `SELECT id::text FROM nodes WHERE cardinality(ancestor_ids) = 10 ORDER BY random() LIMIT 3000`)
	if err != nil {
		t.Fatal(err)
	}
	var leaves []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		leaves = append(leaves, id)
	}
	rows.Close()

	// Isınma
	for i := 0; i < 200; i++ {
		_, _ = svc.Check(ctx, user, leaves[i], Read)
	}

	// 1) Sıralı ölçüm
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
	fmt.Printf("sonuç dağılımı: %d izinli, %d reddedilen\n", allowed, len(leaves)-allowed)
	p95seq := summarize("sıralı (1 istemci)", seq)

	// 2) Eşzamanlı ölçüm: 8 istemci x 500 istek
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
					t.Error(err)
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

	// 3) EXPLAIN (ANALYZE)
	er, err := pool.Query(ctx, "EXPLAIN (ANALYZE, BUFFERS) "+rulesSQL, leaves[0], user)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("--- EXPLAIN (ANALYZE, BUFFERS) ---")
	for er.Next() {
		var line string
		_ = er.Scan(&line)
		fmt.Println(line)
	}
	er.Close()

	if p95seq >= 30*time.Millisecond || p95par >= 30*time.Millisecond {
		t.Fatalf("p95 hedefi aşıldı: sıralı=%v eşzamanlı=%v (hedef < 30ms)", p95seq, p95par)
	}
}
