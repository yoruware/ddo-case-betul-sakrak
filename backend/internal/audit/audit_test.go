package audit_test

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/yoruware/ddo-case-betul-sakrak/backend/internal/audit"
	"github.com/yoruware/ddo-case-betul-sakrak/backend/internal/testutil"
)

func TestZincir(t *testing.T) {
	ctx := context.Background()
	pool := testutil.NewPool(t)
	svc := audit.New(pool)

	mustExec := func(q string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("boş zincir geçerlidir", func(t *testing.T) {
		res, err := svc.Verify(ctx)
		if err != nil || !res.Valid || res.Checked != 0 {
			t.Fatalf("beklenmeyen sonuç: %+v, %v", res, err)
		}
	})

	t.Run("eşzamanlı eklemeler zinciri bozmaz", func(t *testing.T) {
		var wg sync.WaitGroup
		for g := 0; g < 20; g++ {
			wg.Add(1)
			go func(g int) {
				defer wg.Done()
				for i := 0; i < 5; i++ {
					err := svc.Append(ctx, audit.Entry{
						ActorID: "u", Action: "test.append", TargetType: "x",
						TargetID: fmt.Sprintf("%d-%d", g, i), New: map[string]int{"i": i},
					})
					if err != nil {
						t.Error(err)
					}
				}
			}(g)
		}
		wg.Wait()
		res, err := svc.Verify(ctx)
		if err != nil || !res.Valid || res.Checked != 100 {
			t.Fatalf("100 geçerli kayıt bekleniyordu: %+v, %v", res, err)
		}
	})

	t.Run("UPDATE, DELETE ve TRUNCATE reddedilir", func(t *testing.T) {
		for _, q := range []string{
			`UPDATE audit_log SET action = 'x' WHERE seq = 1`,
			`DELETE FROM audit_log WHERE seq = 1`,
			`TRUNCATE audit_log`,
		} {
			if _, err := pool.Exec(ctx, q); err == nil {
				t.Fatalf("reddedilmeliydi: %s", q)
			}
		}
	})

	t.Run("içerik değişikliği tespit edilir", func(t *testing.T) {
		mustExec(`ALTER TABLE audit_log DISABLE TRIGGER USER`)
		var orig string
		if err := pool.QueryRow(ctx, `SELECT new_value FROM audit_log WHERE seq = 10`).Scan(&orig); err != nil {
			t.Fatal(err)
		}
		mustExec(`UPDATE audit_log SET new_value = 'hacked' WHERE seq = 10`)
		res, err := svc.Verify(ctx)
		if err != nil || res.Valid || res.BrokenSeq == nil || *res.BrokenSeq != 10 {
			t.Fatalf("seq 10'da bozulma bekleniyordu: %+v, %v", res, err)
		}
		mustExec(`UPDATE audit_log SET new_value = $1 WHERE seq = 10`, orig)
		res, err = svc.Verify(ctx)
		if err != nil || !res.Valid {
			t.Fatalf("geri alınca geçerli olmalıydı: %+v, %v", res, err)
		}
		mustExec(`ALTER TABLE audit_log ENABLE TRIGGER USER`)
	})

	t.Run("ortadan satır silinmesi tespit edilir", func(t *testing.T) {
		mustExec(`ALTER TABLE audit_log DISABLE TRIGGER USER`)
		mustExec(`DELETE FROM audit_log WHERE seq = 20`)
		res, err := svc.Verify(ctx)
		if err != nil || res.Valid || res.BrokenSeq == nil || *res.BrokenSeq != 21 {
			t.Fatalf("seq 21'de kopukluk bekleniyordu: %+v, %v", res, err)
		}
		mustExec(`ALTER TABLE audit_log ENABLE TRIGGER USER`)
	})
}
