package db

import (
	"database/sql"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/yoruware/ddo-case-betul-sakrak/backend/migrations"
)

func Migrate(dsn string) error {
	conn, err := sql.Open("pgx", dsn)
	if err != nil {
		return err
	}
	defer conn.Close()

	goose.SetBaseFS(migrations.FS)
	if err := goose.SetDialect("postgres"); err != nil {
		return err
	}
	return goose.Up(conn, ".")
}
