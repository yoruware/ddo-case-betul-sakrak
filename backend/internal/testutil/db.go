package testutil

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/yoruware/ddo-case-betul-sakrak/backend/internal/db"
)

// NewPool: gerçek bir PostgreSQL 16 konteyneri başlatır, migrasyonları uygular
// ve bağlantı havuzunu döndürür. Test bitince konteyner kaldırılır.
func NewPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	ctx := context.Background()

	ctr, err := postgres.Run(ctx, "postgres:16-alpine",
		postgres.WithDatabase("test"),
		postgres.WithUsername("test"),
		postgres.WithPassword("test"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(90*time.Second)),
	)
	if err != nil {
		t.Fatalf("postgres konteyneri başlatılamadı (Docker açık mı?): %v", err)
	}
	t.Cleanup(func() { _ = ctr.Terminate(context.Background()) })

	dsn, err := ctr.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("bağlantı adresi alınamadı: %v", err)
	}
	if err := db.Migrate(dsn); err != nil {
		t.Fatalf("migrasyon başarısız: %v", err)
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("havuz oluşturulamadı: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}
