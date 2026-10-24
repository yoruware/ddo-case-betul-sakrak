package auth

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

const DemoPassword = "Demo1234!"

var demoUsers = []struct{ Email, Name, Role string }{
	{"calisan@kasadoc.local", "Ayşe Çalışan", "employee"},
	{"yonetici@kasadoc.local", "Mehmet Yönetici", "unit_manager"},
	{"arsiv@kasadoc.local", "Zeynep Arşiv", "archivist"},
	{"hukuk@kasadoc.local", "Can Hukuk", "legal"},
	{"denetci@kasadoc.local", "Elif Denetçi", "auditor"},
	{"admin@kasadoc.local", "Sistem Yöneticisi", "admin"},
}

func SeedUsers(ctx context.Context, pool *pgxpool.Pool) error {
	var n int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM users").Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	for _, u := range demoUsers {
		h, err := HashPassword(DemoPassword)
		if err != nil {
			return err
		}
		_, err = pool.Exec(ctx,
			`INSERT INTO users (email, password_hash, full_name, role) VALUES ($1,$2,$3,$4)`,
			u.Email, h, u.Name, u.Role)
		if err != nil {
			return err
		}
	}
	return nil
}