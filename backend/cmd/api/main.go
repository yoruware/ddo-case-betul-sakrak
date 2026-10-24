package main

import (
	"context"
	"encoding/json"
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
)

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// Tutarlı hata biçimi: {"error":{"code":"...","message":"..."}}
func writeError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]any{
		"error": map[string]string{"code": code, "message": msg},
	})
}

func cors(origin string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Idempotency-Key")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func healthHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := pool.Ping(ctx); err != nil {
			slog.Error("health: veritabanı erişilemiyor", "err", err)
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{
				"status": "unhealthy", "database": "down",
			})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{
			"status": "ok", "database": "up",
		})
	}
}

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		slog.Error("DATABASE_URL tanımlı değil")
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		slog.Error("veritabanı havuzu oluşturulamadı", "err", err)
		os.Exit(1)
	}
	defer pool.Close()

	if err := db.Migrate(dbURL); err != nil {
		slog.Error("migrasyon başarısız", "err", err)
		os.Exit(1)
	}
	if err := auth.SeedUsers(ctx, pool); err != nil {
		slog.Error("seed başarısız", "err", err)
		os.Exit(1)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", healthHandler(pool))

	srv := &http.Server{
		Addr:              ":" + env("APP_PORT", "8080"),
		Handler:           cors(env("CORS_ALLOWED_ORIGIN", "http://localhost:3000"), mux),
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
