package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yoruware/ddo-case-betul-sakrak/backend/internal/audit"
	"github.com/yoruware/ddo-case-betul-sakrak/backend/internal/auth"
	"github.com/yoruware/ddo-case-betul-sakrak/backend/internal/db"
	"github.com/yoruware/ddo-case-betul-sakrak/backend/internal/download"
	httpapi "github.com/yoruware/ddo-case-betul-sakrak/backend/internal/http"
	"github.com/yoruware/ddo-case-betul-sakrak/backend/internal/permissions"
	"github.com/yoruware/ddo-case-betul-sakrak/backend/internal/retention"
	"github.com/yoruware/ddo-case-betul-sakrak/backend/internal/storage"
	"github.com/yoruware/ddo-case-betul-sakrak/backend/internal/upload"
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
	signKey := os.Getenv("DOWNLOAD_SIGNING_KEY")
	if len(signKey) < 32 {
		fatal("DOWNLOAD_SIGNING_KEY en az 32 karakter olmalı", errors.New("zayıf anahtar"))
	}
	accessTTL, err := time.ParseDuration(env("ACCESS_TOKEN_TTL", "15m"))
	if err != nil {
		fatal("ACCESS_TOKEN_TTL geçersiz", err)
	}
	refreshTTL, err := time.ParseDuration(env("REFRESH_TOKEN_TTL", "168h"))
	if err != nil {
		fatal("REFRESH_TOKEN_TTL geçersiz", err)
	}
	linkTTL, err := time.ParseDuration(env("DOWNLOAD_LINK_TTL", "5m"))
	if err != nil {
		fatal("DOWNLOAD_LINK_TTL geçersiz", err)
	}
	maxUpload, err := strconv.ParseInt(env("MAX_UPLOAD_BYTES", "26214400"), 10, 64)
	if err != nil || maxUpload < 1 {
		fatal("MAX_UPLOAD_BYTES geçersiz", errors.New("pozitif tam sayı olmalı"))
	}
	limits := upload.DefaultLimits()
	limits.MaxFileBytes = maxUpload

	store, err := storage.New(env("STORAGE_DIR", "/data/storage"))
	if err != nil {
		fatal("saklama dizini hazırlanamadı", err)
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

	auditSvc := audit.New(pool)
	retSvc := retention.New(pool, auditSvc, store)

	// Zamanlanmış imha: RETENTION_INTERVAL=0 ile kapatılır.
	if iv := env("RETENTION_INTERVAL", "1h"); iv != "0" {
		every, err := time.ParseDuration(iv)
		if err != nil || every < time.Second {
			fatal("RETENTION_INTERVAL geçersiz", errors.New("en az 1s olmalı veya 0"))
		}
		go func() {
			t := time.NewTicker(every)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					res, err := retSvc.Run(ctx, "system:retention", 500)
					if err != nil {
						slog.Error("zamanlanmış imha başarısız", "err", err)
						continue
					}
					slog.Info("zamanlanmış imha tamamlandı", "checked", res.Checked,
						"destroyed", res.Destroyed, "blocked_by_hold", res.BlockedByHold, "failed", res.Failed)
				}
			}
		}()
	}

	handler := httpapi.NewRouter(httpapi.Deps{
		Pool:       pool,
		Tokens:     auth.NewTokenService(secret, accessTTL, refreshTTL),
		Perms:      permissions.New(pool),
		Audit:      auditSvc,
		Store:      store,
		Signer:     download.NewSigner(signKey, linkTTL),
		Retention:  retSvc,
		Limits:     limits,
		CORSOrigin: env("CORS_ALLOWED_ORIGIN", "http://localhost:3000"),
	})

	srv := &http.Server{
		Addr:              ":" + env("APP_PORT", "8080"),
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       2 * time.Minute,
		WriteTimeout:      2 * time.Minute,
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
