package db

import (
	"database/sql"
	"errors"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/yoruware/ddo-case-betul-sakrak/backend/migrations"
)

func Migrate(dsn string) (retErr error) {
	conn, err := sql.Open("pgx", dsn)
	if err != nil {
		return err
	}

	defer func() {
		if err := conn.Close(); err != nil {
			retErr = errors.Join(retErr, err)
		}
	}()

	goose.SetBaseFS(migrations.FS)
	if err := goose.SetDialect("postgres"); err != nil {
		return err
	}
	return goose.Up(conn, ".")
}
