package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var Genesis = strings.Repeat("0", 64)

const lockKey = 727001

type Entry struct {
	ActorID    string
	Action     string
	TargetType string
	TargetID   string
	Old, New   any
}

type Row struct {
	Seq        int64     `json:"seq"`
	TS         time.Time `json:"ts"`
	ActorID    string    `json:"actor_id"`
	Action     string    `json:"action"`
	TargetType string    `json:"target_type"`
	TargetID   string    `json:"target_id"`
	OldValue   string    `json:"old_value"`
	NewValue   string    `json:"new_value"`
	PrevHash   string    `json:"prev_hash"`
	Hash       string    `json:"hash"`
}

type VerifyResult struct {
	Valid     bool   `json:"valid"`
	Checked   int64  `json:"checked"`
	HeadHash  string `json:"head_hash"`
	BrokenSeq *int64 `json:"broken_seq,omitempty"`
	Reason    string `json:"reason,omitempty"`
}

type Service struct{ pool *pgxpool.Pool }

func New(pool *pgxpool.Pool) *Service { return &Service{pool: pool} }

func canon(v any) (string, error) {
	if v == nil {
		return "", nil
	}
	b, err := json.Marshal(v)
	return string(b), err
}

// Alanlar uzunluk önekiyle birleştirilir: "ab"+"c" ile "a"+"bc" aynı hash'i vermez.
func computeHash(prev string, ts time.Time, actor, action, tt, tid, oldV, newV string) string {
	h := sha256.New()
	for _, part := range []string{prev, ts.UTC().Format(time.RFC3339Nano), actor, action, tt, tid, oldV, newV} {
		h.Write([]byte(strconv.Itoa(len(part))))
		h.Write([]byte{':'})
		h.Write([]byte(part))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// AppendTx: iş işlemiyle aynı transaction içinde yazılır; iş geri alınırsa kayıt da geri alınır.
func (s *Service) AppendTx(ctx context.Context, tx pgx.Tx, e Entry) error {
	oldS, err := canon(e.Old)
	if err != nil {
		return err
	}
	newS, err := canon(e.New)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, lockKey); err != nil {
		return err
	}
	prev := Genesis
	err = tx.QueryRow(ctx, `SELECT hash FROM audit_log ORDER BY seq DESC LIMIT 1`).Scan(&prev)
	if errors.Is(err, pgx.ErrNoRows) {
		prev = Genesis
	} else if err != nil {
		return err
	}
	ts := time.Now().UTC().Truncate(time.Microsecond)
	h := computeHash(prev, ts, e.ActorID, e.Action, e.TargetType, e.TargetID, oldS, newS)
	_, err = tx.Exec(ctx, `
INSERT INTO audit_log (ts, actor_id, action, target_type, target_id, old_value, new_value, prev_hash, hash)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		ts, e.ActorID, e.Action, e.TargetType, e.TargetID, oldS, newS, prev, h)
	return err
}

func (s *Service) Append(ctx context.Context, e Entry) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := s.AppendTx(ctx, tx, e); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Service) Verify(ctx context.Context) (VerifyResult, error) {
	res := VerifyResult{Valid: true, HeadHash: Genesis}
	rows, err := s.pool.Query(ctx, `
SELECT seq, ts, actor_id, action, target_type, target_id, old_value, new_value, prev_hash, hash
FROM audit_log ORDER BY seq`)
	if err != nil {
		return res, err
	}
	defer rows.Close()

	prev := Genesis
	for rows.Next() {
		var r Row
		if err := rows.Scan(&r.Seq, &r.TS, &r.ActorID, &r.Action, &r.TargetType, &r.TargetID,
			&r.OldValue, &r.NewValue, &r.PrevHash, &r.Hash); err != nil {
			return res, err
		}
		res.Checked++
		if r.PrevHash != prev {
			seq := r.Seq
			return VerifyResult{Valid: false, Checked: res.Checked, BrokenSeq: &seq,
				Reason: "zincir kopuk: önceki hash uyuşmuyor (satır silinmiş veya eklenmiş olabilir)"}, nil
		}
		want := computeHash(prev, r.TS, r.ActorID, r.Action, r.TargetType, r.TargetID, r.OldValue, r.NewValue)
		if want != r.Hash {
			seq := r.Seq
			return VerifyResult{Valid: false, Checked: res.Checked, BrokenSeq: &seq,
				Reason: "satır içeriği değiştirilmiş: hash uyuşmuyor"}, nil
		}
		prev = r.Hash
		res.HeadHash = r.Hash
	}
	return res, rows.Err()
}

func (s *Service) List(ctx context.Context, after int64, limit int) ([]Row, error) {
	rows, err := s.pool.Query(ctx, `
SELECT seq, ts, actor_id, action, target_type, target_id, old_value, new_value, prev_hash, hash
FROM audit_log WHERE seq > $1 ORDER BY seq LIMIT $2`, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Row{}
	for rows.Next() {
		var r Row
		if err := rows.Scan(&r.Seq, &r.TS, &r.ActorID, &r.Action, &r.TargetType, &r.TargetID,
			&r.OldValue, &r.NewValue, &r.PrevHash, &r.Hash); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}