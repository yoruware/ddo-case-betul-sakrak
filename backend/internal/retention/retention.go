package retention

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yoruware/ddo-case-betul-sakrak/backend/internal/audit"
	"github.com/yoruware/ddo-case-betul-sakrak/backend/internal/storage"
)

// LockKey: imha, bekletme ve yükleme işlemlerini sıraya dizen advisory kilit anahtarı.
// Kilit sırası her yerde aynıdır: önce LockKey, sonra denetim kilidi (kilitlenme olmaz).
const LockKey = 727002

var (
	ErrNotFound        = errors.New("kayıt bulunamadı")
	ErrNotFile         = errors.New("düğüm bir dosya değil veya imha edilmiş")
	ErrUnknownDocType  = errors.New("bilinmeyen belge türü")
	ErrAlreadyAssigned = errors.New("saklama kaydı zaten var")
	ErrDestroyed       = errors.New("düğüm imha edilmiş")
)

type Service struct {
	pool  *pgxpool.Pool
	audit *audit.Service
	store *storage.Store
}

func New(pool *pgxpool.Pool, a *audit.Service, st *storage.Store) *Service {
	return &Service{pool: pool, audit: a, store: st}
}

func (s *Service) lock(ctx context.Context, tx pgx.Tx) error {
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, LockKey)
	return err
}

func collect(rows pgx.Rows) ([]string, error) {
	defer rows.Close()
	var out []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func ts(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

// AssignRetention: dosyaya belge türü atar; retention_until = oluşturma tarihi + tür süresi.
// Kayıt bir kez atanır (kısaltma yoluyla erken imha riskini önlemek için).
func (s *Service) AssignRetention(ctx context.Context, actor, nodeID, docType string) (time.Time, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return time.Time{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var okFile bool
	err = tx.QueryRow(ctx, `SELECT kind = 'file' AND destroyed_at IS NULL FROM nodes WHERE id = $1::uuid`, nodeID).Scan(&okFile)
	if errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, ErrNotFound
	}
	if err != nil {
		return time.Time{}, err
	}
	if !okFile {
		return time.Time{}, ErrNotFile
	}
	var typeOK bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM document_types WHERE code = $1)`, docType).Scan(&typeOK); err != nil {
		return time.Time{}, err
	}
	if !typeOK {
		return time.Time{}, ErrUnknownDocType
	}
	var until time.Time
	err = tx.QueryRow(ctx, `
INSERT INTO retention_records (node_id, doc_type, retention_until, assigned_by)
SELECT n.id, d.code, n.created_at + make_interval(days => d.retention_days), $3::uuid
FROM nodes n, document_types d
WHERE n.id = $1::uuid AND d.code = $2
ON CONFLICT (node_id) DO NOTHING
RETURNING retention_until`, nodeID, docType, actor).Scan(&until)
	if errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, ErrAlreadyAssigned
	}
	if err != nil {
		return time.Time{}, err
	}
	err = s.audit.AppendTx(ctx, tx, audit.Entry{
		ActorID: actor, Action: "retention.assigned", TargetType: "node", TargetID: nodeID,
		New: map[string]any{"doc_type": docType, "retention_until": ts(until)},
	})
	if err != nil {
		return time.Time{}, err
	}
	return until, tx.Commit(ctx)
}

// PlaceHold: düğüme (ve altındaki her şeye) hukuki bekletme koyar.
func (s *Service) PlaceHold(ctx context.Context, actor, nodeID, caseRef, reason string) (string, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := s.lock(ctx, tx); err != nil {
		return "", err
	}
	var destroyed bool
	err = tx.QueryRow(ctx, `SELECT destroyed_at IS NOT NULL FROM nodes WHERE id = $1::uuid`, nodeID).Scan(&destroyed)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}
	if destroyed {
		return "", ErrDestroyed
	}
	var id string
	err = tx.QueryRow(ctx, `
INSERT INTO legal_holds (node_id, case_ref, reason, placed_by)
VALUES ($1::uuid, $2, $3, $4::uuid) RETURNING id::text`, nodeID, caseRef, reason, actor).Scan(&id)
	if err != nil {
		return "", err
	}
	err = s.audit.AppendTx(ctx, tx, audit.Entry{
		ActorID: actor, Action: "legal_hold.placed", TargetType: "node", TargetID: nodeID,
		New: map[string]any{"hold_id": id, "case_ref": caseRef, "reason": reason},
	})
	if err != nil {
		return "", err
	}
	return id, tx.Commit(ctx)
}

// ReleaseHold: bekletmeyi kaldırır. Zaten kaldırılmışsa (false, nil) döner.
func (s *Service) ReleaseHold(ctx context.Context, actor, holdID string) (bool, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := s.lock(ctx, tx); err != nil {
		return false, err
	}
	var nodeID, caseRef string
	err = tx.QueryRow(ctx, `
UPDATE legal_holds SET released_at = now(), released_by = $2::uuid
WHERE id = $1::uuid AND released_at IS NULL
RETURNING node_id::text, case_ref`, holdID, actor).Scan(&nodeID, &caseRef)
	if errors.Is(err, pgx.ErrNoRows) {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM legal_holds WHERE id = $1::uuid)`, holdID).Scan(&exists); err != nil {
			return false, err
		}
		if !exists {
			return false, ErrNotFound
		}
		return false, nil
	}
	if err != nil {
		return false, err
	}
	// Engellenmiş kayıtlar sıfırlanır: yeni bir bekletme tekrar engellenirse yeniden denetim kaydı yazılır.
	_, err = tx.Exec(ctx, `
UPDATE retention_records r SET hold_blocked_at = NULL
FROM nodes n WHERE n.id = r.node_id AND $1::uuid = ANY(n.ancestor_ids)`, nodeID)
	if err != nil {
		return false, err
	}
	err = s.audit.AppendTx(ctx, tx, audit.Entry{
		ActorID: actor, Action: "legal_hold.released", TargetType: "node", TargetID: nodeID,
		Old: map[string]any{"hold_id": holdID, "case_ref": caseRef},
	})
	if err != nil {
		return false, err
	}
	return true, tx.Commit(ctx)
}

type RunResult struct {
	Checked       int      `json:"checked"`
	Destroyed     int      `json:"destroyed"`
	BlockedByHold int      `json:"blocked_by_hold"`
	Failed        int      `json:"failed"`
	Certificates  []string `json:"certificates"`
}

// Run: süresi dolan belgeleri imha eder. Tekrar veya eşzamanlı çalıştırmak güvenlidir.
func (s *Service) Run(ctx context.Context, actor string, limit int) (RunResult, error) {
	res := RunResult{Certificates: []string{}}
	rows, err := s.pool.Query(ctx, `
SELECT r.node_id::text FROM retention_records r JOIN nodes n ON n.id = r.node_id
WHERE n.destroyed_at IS NULL AND r.retention_until <= now()
ORDER BY r.retention_until, r.node_id LIMIT $1`, limit)
	if err != nil {
		return res, err
	}
	ids, err := collect(rows)
	if err != nil {
		return res, err
	}
	res.Checked = len(ids)
	for _, id := range ids {
		out, certID, err := s.destroyOne(ctx, actor, id)
		switch {
		case err != nil:
			res.Failed++
			slog.Error("imha başarısız", "node_id", id, "err", err)
		case out == outDestroyed:
			res.Destroyed++
			res.Certificates = append(res.Certificates, certID)
		case out == outBlocked:
			res.BlockedByHold++
		}
	}
	if res.Destroyed > 0 {
		err := s.audit.Append(ctx, audit.Entry{
			ActorID: actor, Action: "retention.run", TargetType: "system", TargetID: "retention", New: res,
		})
		if err != nil {
			return res, err
		}
	}
	return res, nil
}

type outcome int

const (
	outSkipped outcome = iota
	outDestroyed
	outBlocked
)

type trashed struct{ sha, path string }

type versionEvidence struct {
	VersionNo   int    `json:"version_no"`
	SHA256      string `json:"sha256"`
	SizeBytes   int64  `json:"size_bytes"`
	BlobRemoved bool   `json:"blob_removed"`
	SharedBlob  bool   `json:"shared_blob"`
}

type certBody struct {
	CertificateID     string            `json:"certificate_id"`
	NodeID            string            `json:"node_id"`
	Name              string            `json:"name"`
	DocType           string            `json:"doc_type"`
	RetentionUntil    string            `json:"retention_until"`
	DestroyedAt       string            `json:"destroyed_at"`
	ExecutedBy        string            `json:"executed_by"`
	Versions          []versionEvidence `json:"versions"`
	RevokedShareLinks int64             `json:"revoked_share_links"`
}

type certAudit struct {
	Certificate certBody `json:"certificate"`
	BodyHash    string   `json:"body_hash"`
}

func (s *Service) destroyOne(ctx context.Context, actor, nodeID string) (outcome, string, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return outSkipped, "", err
	}
	var moved []trashed
	committed := false
	defer func() {
		_ = tx.Rollback(ctx)
		for _, m := range moved {
			if committed {
				if perr := s.store.Purge(m.path); perr != nil {
					slog.Error("çöp dosyası silinemedi", "path", m.path, "err", perr)
				}
			} else if rerr := s.store.Restore(m.path, m.sha); rerr != nil {
				slog.Error("blob geri konulamadı", "sha256", m.sha, "err", rerr)
			}
		}
	}()

	if err := s.lock(ctx, tx); err != nil {
		return outSkipped, "", err
	}

	// Kilit altında yeniden kontrol: başka bir çalıştırma bu belgeyi zaten imha etmiş olabilir.
	var name, docType string
	var until time.Time
	err = tx.QueryRow(ctx, `
SELECT n.name, r.doc_type, r.retention_until
FROM retention_records r JOIN nodes n ON n.id = r.node_id
WHERE r.node_id = $1::uuid AND n.destroyed_at IS NULL AND r.retention_until <= now()
FOR UPDATE OF n, r`, nodeID).Scan(&name, &docType, &until)
	if errors.Is(err, pgx.ErrNoRows) {
		return outSkipped, "", nil
	}
	if err != nil {
		return outSkipped, "", err
	}

	hrows, err := tx.Query(ctx, `
SELECT h.id::text FROM legal_holds h JOIN nodes n ON n.id = $1::uuid
WHERE h.released_at IS NULL AND h.node_id = ANY(n.ancestor_ids)`, nodeID)
	if err != nil {
		return outSkipped, "", err
	}
	holds, err := collect(hrows)
	if err != nil {
		return outSkipped, "", err
	}
	if len(holds) > 0 {
		var marked string
		merr := tx.QueryRow(ctx, `
UPDATE retention_records SET hold_blocked_at = now()
WHERE node_id = $1::uuid AND hold_blocked_at IS NULL RETURNING node_id::text`, nodeID).Scan(&marked)
		if merr == nil { // ilk engelleme: bir kez kaydedilir, tekrar çalıştırmalar kaydı şişirmez
			err := s.audit.AppendTx(ctx, tx, audit.Entry{
				ActorID: actor, Action: "retention.blocked_by_hold", TargetType: "node", TargetID: nodeID,
				New: map[string]any{"name": name, "doc_type": docType, "retention_until": ts(until), "hold_ids": holds},
			})
			if err != nil {
				return outSkipped, "", err
			}
			if err := tx.Commit(ctx); err != nil {
				return outSkipped, "", err
			}
			committed = true
		} else if !errors.Is(merr, pgx.ErrNoRows) {
			return outSkipped, "", merr
		}
		return outBlocked, "", nil
	}

	vrows, err := tx.Query(ctx, `
SELECT version_no, sha256, size_bytes FROM file_versions WHERE node_id = $1::uuid ORDER BY version_no`, nodeID)
	if err != nil {
		return outSkipped, "", err
	}
	var versions []versionEvidence
	for vrows.Next() {
		var v versionEvidence
		if err := vrows.Scan(&v.VersionNo, &v.SHA256, &v.SizeBytes); err != nil {
			vrows.Close()
			return outSkipped, "", err
		}
		versions = append(versions, v)
	}
	vrows.Close()
	if err := vrows.Err(); err != nil {
		return outSkipped, "", err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM file_versions WHERE node_id = $1::uuid`, nodeID); err != nil {
		return outSkipped, "", err
	}

	// Blob yalnızca başka hiçbir sürüm kullanmıyorsa silinir (içerik adresli saklamada referans sayımı).
	seen := map[string]versionEvidence{}
	for i := range versions {
		v := &versions[i]
		if prev, ok := seen[v.SHA256]; ok {
			v.BlobRemoved, v.SharedBlob = prev.BlobRemoved, prev.SharedBlob
			continue
		}
		tag, err := tx.Exec(ctx, `
DELETE FROM blobs WHERE sha256 = $1
  AND NOT EXISTS (SELECT 1 FROM file_versions fv WHERE fv.sha256 = $1)`, v.SHA256)
		if err != nil {
			return outSkipped, "", err
		}
		if tag.RowsAffected() == 0 {
			v.SharedBlob = true
		} else {
			p, err := s.store.Trash(v.SHA256)
			if err != nil {
				return outSkipped, "", err
			}
			if p != "" {
				moved = append(moved, trashed{sha: v.SHA256, path: p})
				v.BlobRemoved = true
			}
		}
		seen[v.SHA256] = *v
	}

	tag, err := tx.Exec(ctx, `UPDATE share_links SET revoked_at = now() WHERE node_id = $1::uuid AND revoked_at IS NULL`, nodeID)
	if err != nil {
		return outSkipped, "", err
	}
	var destroyedAt time.Time
	err = tx.QueryRow(ctx, `UPDATE nodes SET destroyed_at = now() WHERE id = $1::uuid RETURNING destroyed_at`, nodeID).Scan(&destroyedAt)
	if err != nil {
		return outSkipped, "", err
	}
	var certID string
	if err := tx.QueryRow(ctx, `SELECT gen_random_uuid()::text`).Scan(&certID); err != nil {
		return outSkipped, "", err
	}

	body := certBody{
		CertificateID: certID, NodeID: nodeID, Name: name, DocType: docType,
		RetentionUntil: ts(until), DestroyedAt: ts(destroyedAt), ExecutedBy: actor,
		Versions: versions, RevokedShareLinks: tag.RowsAffected(),
	}
	bj, err := json.Marshal(body)
	if err != nil {
		return outSkipped, "", err
	}
	sum := sha256.Sum256(bj)
	bodyHash := hex.EncodeToString(sum[:])

	seq, auditHash, err := s.audit.AppendTxRef(ctx, tx, audit.Entry{
		ActorID: actor, Action: "retention.destroyed", TargetType: "node", TargetID: nodeID,
		New: certAudit{Certificate: body, BodyHash: bodyHash},
	})
	if err != nil {
		return outSkipped, "", err
	}
	_, err = tx.Exec(ctx, `
INSERT INTO destruction_certificates (id, node_id, node_name, doc_type, body, body_hash, audit_seq, audit_hash)
VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8)`,
		certID, nodeID, name, docType, string(bj), bodyHash, seq, auditHash)
	if err != nil {
		return outSkipped, "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return outSkipped, "", err
	}
	committed = true
	return outDestroyed, certID, nil
}

type Verification struct {
	BodyHashValid      bool `json:"body_hash_valid"`
	AuditRecordFound   bool `json:"audit_record_found"`
	AuditRecordMatches bool `json:"audit_record_matches"`
	Valid              bool `json:"valid"`
}

type CertificateView struct {
	ID           string          `json:"id"`
	NodeID       string          `json:"node_id"`
	Body         json.RawMessage `json:"body"`
	BodyHash     string          `json:"body_hash"`
	AuditSeq     int64           `json:"audit_seq"`
	AuditHash    string          `json:"audit_hash"`
	CreatedAt    time.Time       `json:"created_at"`
	Verification Verification    `json:"verification"`
}

// GetCertificate: tutanağı döndürür ve hash'ini ile denetim zincirindeki kaydı doğrular.
func (s *Service) GetCertificate(ctx context.Context, id string) (*CertificateView, error) {
	var v CertificateView
	var body string
	err := s.pool.QueryRow(ctx, `
SELECT id::text, node_id::text, body, body_hash, audit_seq, audit_hash, created_at
FROM destruction_certificates WHERE id = $1::uuid`, id).
		Scan(&v.ID, &v.NodeID, &body, &v.BodyHash, &v.AuditSeq, &v.AuditHash, &v.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if json.Valid([]byte(body)) {
		v.Body = json.RawMessage(body)
	} else {
		v.Body = json.RawMessage("null")
	}
	sum := sha256.Sum256([]byte(body))
	v.Verification.BodyHashValid = hex.EncodeToString(sum[:]) == v.BodyHash

	var h, nv, action string
	aerr := s.pool.QueryRow(ctx, `SELECT hash, new_value, action FROM audit_log WHERE seq = $1`, v.AuditSeq).Scan(&h, &nv, &action)
	switch {
	case aerr == nil:
		v.Verification.AuditRecordFound = true
		v.Verification.AuditRecordMatches = h == v.AuditHash && action == "retention.destroyed" && strings.Contains(nv, v.BodyHash)
	case !errors.Is(aerr, pgx.ErrNoRows):
		return nil, aerr
	}
	v.Verification.Valid = v.Verification.BodyHashValid && v.Verification.AuditRecordFound && v.Verification.AuditRecordMatches
	return &v, nil
}

type CertificateSummary struct {
	ID        string    `json:"id"`
	NodeID    string    `json:"node_id"`
	NodeName  string    `json:"node_name"`
	DocType   string    `json:"doc_type"`
	BodyHash  string    `json:"body_hash"`
	AuditSeq  int64     `json:"audit_seq"`
	CreatedAt time.Time `json:"created_at"`
}

func (s *Service) ListCertificates(ctx context.Context) ([]CertificateSummary, error) {
	rows, err := s.pool.Query(ctx, `
SELECT id::text, node_id::text, node_name, doc_type, body_hash, audit_seq, created_at
FROM destruction_certificates ORDER BY created_at DESC LIMIT 200`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []CertificateSummary{}
	for rows.Next() {
		var c CertificateSummary
		if err := rows.Scan(&c.ID, &c.NodeID, &c.NodeName, &c.DocType, &c.BodyHash, &c.AuditSeq, &c.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
