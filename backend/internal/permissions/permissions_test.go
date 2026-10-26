package permissions

import "testing"

func TestResolve(t *testing.T) {
	cases := []struct {
		name  string
		rules []Rule
		perm  string
		want  bool
	}{
		{"kayıt yok: reddedilir", nil, Read, false},
		{"yalnızca allow: izin verilir", []Rule{{Read, "allow"}}, Read, true},
		{"yalnızca deny: reddedilir", []Rule{{Read, "deny"}}, Read, false},
		{"deny kazanır (allow önce)", []Rule{{Read, "allow"}, {Read, "deny"}}, Read, false},
		{"deny kazanır (deny önce)", []Rule{{Read, "deny"}, {Read, "allow"}}, Read, false},
		{"başka izin etkilenmez", []Rule{{Read, "deny"}, {Write, "allow"}}, Write, true},
		{"verilmeyen izin yok", []Rule{{Read, "allow"}}, Write, false},
		{"bilinmeyen etki yok sayılır", []Rule{{Read, "belki"}}, Read, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Resolve(c.rules)[c.perm]; got != c.want {
				t.Fatalf("%s: beklenen %v, gelen %v", c.perm, c.want, got)
			}
		})
	}
}

func TestResolveHerZamanTumIzinleriDoner(t *testing.T) {
	set := Resolve(nil)
	if len(set) != len(All) {
		t.Fatalf("beklenen %d izin anahtarı, gelen %d", len(All), len(set))
	}
}

func TestValid(t *testing.T) {
	if !Valid("manage") || Valid("root") || Valid("") {
		t.Fatal("Valid beklenmeyen sonuç verdi")
	}
}
