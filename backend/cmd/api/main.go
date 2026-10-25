package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yoruware/ddo-case-betul-sakrak/backend/internal/auth"
	"github.com/yoruware/ddo-case-betul-sakrak/backend/internal/db"
	httpapi "github.com/yoruware/ddo-case-betul-sakrak/backend/internal/http"
	"github.com/yoruware/ddo-case-betul-sakrak/backend/internal/permissions"
)

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func fatal(msg string, err error) {
	slog.Error(msg, "err", err)
	os.Exit(1)
}

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		fatal("DATABASE_URL tanımlı değil", errors.New("eksik yapılandırma"))
	}
	secret := os.Getenv("JWT_SECRET")
	if len(secret) < 32 {
		fatal("JWT_SECRET en az 32 karakter olmalı", errors.New("zayıf sır"))
	}
	accessTTL, err := time.ParseDuration(env("ACCESS_TOKEN_TTL", "15m"))
	if err != nil {
		fatal("ACCESS_TOKEN_TTL geçersiz", err)
	}
	refreshTTL, err := time.ParseDuration(env("REFRESH_TOKEN_TTL", "168h"))
	if err != nil {
		fatal("REFRESH_TOKEN_TTL geçersiz", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		fatal("veritabanı havuzu oluşturulamadı", err)
	}
	defer pool.Close()

	if err := db.Migrate(dbURL); err != nil {
		fatal("migrasyon başarısız", err)
	}
	if err := auth.SeedUsers(ctx, pool); err != nil {
		fatal("seed başarısız", err)
	}

	handler := httpapi.NewRouter(httpapi.Deps{
		Pool:       pool,
		Tokens:     auth.NewTokenService(secret, accessTTL, refreshTTL),
		Perms:      permissions.New(pool),
		CORSOrigin: env("CORS_ALLOWED_ORIGIN", "http://localhost:3000"),
	})

	srv := &http.Server{
		Addr:              ":" + env("APP_PORT", "8080"),
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		slog.Info("API başlıyor", "addr", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("sunucu hatası", "err", err)
			stop()
		}
	}()

	<-ctx.Done()
	slog.Info("kapanış başlıyor")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("düzgün kapanış başarısız", "err", err)
	}
}
