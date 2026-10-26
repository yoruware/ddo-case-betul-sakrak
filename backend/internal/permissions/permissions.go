package permissions

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	Read   = "read"
	Write  = "write"
	Delete = "delete"
	Share  = "share"
	Manage = "manage"
)

var All = []string{Read, Write, Delete, Share, Manage}

var ErrNotFound = errors.New("düğüm bulunamadı")

func Valid(p string) bool {
	for _, x := range All {
		if x == p {
			return true
		}
	}
	return false
}

// Rule: bir düğümün atalarından (kendisi dahil) kullanıcıya uygulanan tek kayıt.
type Rule struct{ Permission, Effect string }

type Set map[string]bool

// Resolve saf bir fonksiyondur (veritabanı yok), birim testi kolaydır.
// Kural: en az bir allow VE hiç deny yok. Deny her zaman kazanır.
func Resolve(rules []Rule) Set {
	allow := map[string]bool{}
	deny := map[string]bool{}
	for _, r := range rules {
		switch r.Effect {
		case "deny":
			deny[r.Permission] = true
		case "allow":
			allow[r.Permission] = true
		}
	}
	out := make(Set, len(All))
	for _, p := range All {
		out[p] = allow[p] && !deny[p]
	}
	return out
}

type Service struct{ pool *pgxpool.Pool }

func New(pool *pgxpool.Pool) *Service { return &Service{pool: pool} }

// Tek sorgu: düğümün tüm atalarındaki, kullanıcıya veya üyesi olduğu gruplara
// ait kayıtlar. LEFT JOIN sayesinde kayıt olmasa da düğüm varsa bir satır döner.
// Hiç satır dönmezse düğüm yoktur. Sonuç önbelleğe alınmaz.
const rulesSQL = `
SELECT a.permission, a.effect
FROM nodes n
LEFT JOIN acl_entries a
  ON a.node_id = ANY(n.ancestor_ids)
 AND ((a.subject_type = 'user'  AND a.subject_id = $2::uuid)
   OR (a.subject_type = 'group' AND a.subject_id IN
        (SELECT group_id FROM group_members WHERE user_id = $2::uuid)))
WHERE n.id = $1::uuid`

func (s *Service) Effective(ctx context.Context, userID, nodeID string) (Set, error) {
	rows, err := s.pool.Query(ctx, rulesSQL, nodeID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	found := false
	var rules []Rule
	for rows.Next() {
		found = true
		var perm, effect *string
		if err := rows.Scan(&perm, &effect); err != nil {
			return nil, err
		}
		if perm != nil && effect != nil {
			rules = append(rules, Rule{Permission: *perm, Effect: *effect})
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if !found {
		return nil, ErrNotFound
	}
	return Resolve(rules), nil
}

func (s *Service) Check(ctx context.Context, userID, nodeID, perm string) (bool, error) {
	set, err := s.Effective(ctx, userID, nodeID)
	if err != nil {
		return false, err
	}
	return set[perm], nil
}
