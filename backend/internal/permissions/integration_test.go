package permissions_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yoruware/ddo-case-betul-sakrak/backend/internal/permissions"
	"github.com/yoruware/ddo-case-betul-sakrak/backend/internal/testutil"
)

var ctx = context.Background()

func mkUser(t *testing.T, p *pgxpool.Pool, email string) string {
	t.Helper()
	var id string
	err := p.QueryRow(ctx,
		`INSERT INTO users (email, password_hash, full_name, role) VALUES ($1,'x',$1,'employee') RETURNING id::text`,
		email).Scan(&id)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func mkGroup(t *testing.T, p *pgxpool.Pool, name string) string {
	t.Helper()
	var id string
	if err := p.QueryRow(ctx, `INSERT INTO groups (name) VALUES ($1) RETURNING id::text`, name).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func addMember(t *testing.T, p *pgxpool.Pool, group, user string) {
	t.Helper()
	if _, err := p.Exec(ctx, `INSERT INTO group_members (group_id, user_id) VALUES ($1::uuid,$2::uuid)`, group, user); err != nil {
		t.Fatal(err)
	}
}

func mkNode(t *testing.T, p *pgxpool.Pool, parent *string, name, owner string) string {
	t.Helper()
	var id string
	err := p.QueryRow(ctx, `
WITH nid AS (SELECT gen_random_uuid() AS id)
INSERT INTO nodes (id, parent_id, kind, name, owner_id, ancestor_ids)
SELECT nid.id, $1::uuid, 'folder', $2::text, $3::uuid,
       array_append(COALESCE((SELECT ancestor_ids FROM nodes WHERE id = $1::uuid), '{}'::uuid[]), nid.id)
FROM nid RETURNING id::text`, parent, name, owner).Scan(&id)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func grant(t *testing.T, p *pgxpool.Pool, node, subjType, subj, perm, effect, by string) string {
	t.Helper()
	var id string
	err := p.QueryRow(ctx, `
INSERT INTO acl_entries (node_id, subject_type, subject_id, permission, effect, created_by)
VALUES ($1::uuid,$2,$3::uuid,$4,$5,$6::uuid) RETURNING id::text`,
		node, subjType, subj, perm, effect, by).Scan(&id)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func can(t *testing.T, s *permissions.Service, user, node, perm string) bool {
	t.Helper()
	ok, err := s.Check(ctx, user, node, perm)
	if err != nil {
		t.Fatal(err)
	}
	return ok
}

func TestEtkinYetkiEntegrasyon(t *testing.T) {
	pool := testutil.NewPool(t)
	svc := permissions.New(pool)
	admin := mkUser(t, pool, "admin@test")

	t.Run("üst klasördeki allow alttakilere miras kalır", func(t *testing.T) {
		u := mkUser(t, pool, "miras@test")
		root := mkNode(t, pool, nil, "r1", admin)
		mid := mkNode(t, pool, &root, "m1", admin)
		leaf := mkNode(t, pool, &mid, "l1", admin)
		grant(t, pool, root, "user", u, "read", "allow", admin)

		for _, n := range []string{root, mid, leaf} {
			if !can(t, svc, u, n, permissions.Read) {
				t.Fatalf("read miras kalmadı: %s", n)
			}
			if can(t, svc, u, n, permissions.Write) {
				t.Fatalf("verilmeyen write izni görünüyor: %s", n)
			}
		}
	})

	t.Run("alttaki allow üstteki deny'ı aşamaz", func(t *testing.T) {
		u := mkUser(t, pool, "denyust@test")
		root := mkNode(t, pool, nil, "r2", admin)
		child := mkNode(t, pool, &root, "c2", admin)
		grant(t, pool, root, "user", u, "read", "deny", admin)
		grant(t, pool, child, "user", u, "read", "allow", admin)
		if can(t, svc, u, child, permissions.Read) {
			t.Fatal("deny kazanmalıydı")
		}
	})

	t.Run("alttaki deny üst klasörü etkilemez", func(t *testing.T) {
		u := mkUser(t, pool, "denyalt@test")
		root := mkNode(t, pool, nil, "r3", admin)
		child := mkNode(t, pool, &root, "c3", admin)
		grant(t, pool, root, "user", u, "read", "allow", admin)
		grant(t, pool, child, "user", u, "read", "deny", admin)
		if !can(t, svc, u, root, permissions.Read) {
			t.Fatal("üst klasör erişilebilir kalmalıydı")
		}
		if can(t, svc, u, child, permissions.Read) {
			t.Fatal("alt klasör reddedilmeliydi")
		}
	})

	t.Run("grup üyeliği yetki verir, üyelik kalkınca yetki anında biter", func(t *testing.T) {
		u := mkUser(t, pool, "grup@test")
		g := mkGroup(t, pool, "g-test-1")
		root := mkNode(t, pool, nil, "r4", admin)
		child := mkNode(t, pool, &root, "c4", admin)
		grant(t, pool, root, "group", g, "write", "allow", admin)

		if can(t, svc, u, child, permissions.Write) {
			t.Fatal("üye değilken yetki olmamalı")
		}
		addMember(t, pool, g, u)
		if !can(t, svc, u, child, permissions.Write) {
			t.Fatal("üye olunca yetki gelmeli")
		}
		if _, err := pool.Exec(ctx, `DELETE FROM group_members WHERE group_id=$1::uuid AND user_id=$2::uuid`, g, u); err != nil {
			t.Fatal(err)
		}
		if can(t, svc, u, child, permissions.Write) {
			t.Fatal("üyelik kalkınca eski yetkiyle erişim mümkün olmamalı")
		}
	})

	t.Run("gruba konan deny kullanıcıya verilen allow'u geçersiz kılar", func(t *testing.T) {
		u := mkUser(t, pool, "grupdeny@test")
		g := mkGroup(t, pool, "g-test-2")
		addMember(t, pool, g, u)
		root := mkNode(t, pool, nil, "r5", admin)
		grant(t, pool, root, "user", u, "read", "allow", admin)
		grant(t, pool, root, "group", g, "read", "deny", admin)
		if can(t, svc, u, root, permissions.Read) {
			t.Fatal("grup deny'ı kazanmalıydı")
		}
	})

	t.Run("yetki kaydı silinince erişim anında kapanır", func(t *testing.T) {
		u := mkUser(t, pool, "iptal@test")
		root := mkNode(t, pool, nil, "r6", admin)
		leaf := mkNode(t, pool, &root, "l6", admin)
		entry := grant(t, pool, root, "user", u, "read", "allow", admin)
		if !can(t, svc, u, leaf, permissions.Read) {
			t.Fatal("başlangıçta erişim olmalı")
		}
		if _, err := pool.Exec(ctx, `DELETE FROM acl_entries WHERE id=$1::uuid`, entry); err != nil {
			t.Fatal(err)
		}
		if can(t, svc, u, leaf, permissions.Read) {
			t.Fatal("silinen yetkiyle erişim sürüyor")
		}
	})

	t.Run("başka kullanıcının yetkisi sızmaz", func(t *testing.T) {
		a := mkUser(t, pool, "a@test")
		b := mkUser(t, pool, "b@test")
		root := mkNode(t, pool, nil, "r7", admin)
		grant(t, pool, root, "user", a, "read", "allow", admin)
		if can(t, svc, b, root, permissions.Read) {
			t.Fatal("b kullanıcısı a'nın yetkisini görmemeli")
		}
	})

	t.Run("olmayan düğüm ErrNotFound döner", func(t *testing.T) {
		u := mkUser(t, pool, "yok@test")
		var ghost string
		if err := pool.QueryRow(ctx, `SELECT gen_random_uuid()::text`).Scan(&ghost); err != nil {
			t.Fatal(err)
		}
		if _, err := svc.Effective(ctx, u, ghost); !errors.Is(err, permissions.ErrNotFound) {
			t.Fatalf("ErrNotFound bekleniyordu, gelen: %v", err)
		}
	})

	t.Run("ancestor_ids CHECK kısıtı bozuk diziyi reddeder", func(t *testing.T) {
		_, err := pool.Exec(ctx, `
INSERT INTO nodes (parent_id, kind, name, owner_id, ancestor_ids)
VALUES (NULL, 'folder', 'bozuk', $1::uuid, ARRAY[gen_random_uuid()])`, admin)
		if err == nil {
			t.Fatal("kısıt ihlali bekleniyordu")
		}
	})
}
