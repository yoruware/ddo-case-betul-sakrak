package httpapi

import (
	"context"
	"net/http"
	"slices"
	"strings"

	"github.com/yoruware/ddo-case-betul-sakrak/backend/internal/auth"
)

type ctxKey struct{}

type Principal struct {
	UserID string
	Role   string
}

func PrincipalFrom(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(ctxKey{}).(Principal)
	return p, ok
}

func Cors(origin string, next http.Handler) http.Handler {
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

// Authenticate: Bearer access token ister, yoksa 401 döner.
func Authenticate(tokens *auth.TokenService) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := r.Header.Get("Authorization")
			raw, ok := strings.CutPrefix(h, "Bearer ")
			if !ok || raw == "" {
				WriteError(w, http.StatusUnauthorized, "unauthorized", "Kimlik doğrulama gerekli")
				return
			}
			claims, err := tokens.Parse(raw, auth.TypeAccess)
			if err != nil {
				WriteError(w, http.StatusUnauthorized, "unauthorized", "Geçersiz veya süresi dolmuş token")
				return
			}
			p := Principal{UserID: claims.Subject, Role: claims.Role}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, p)))
		})
	}
}

// RequireRole: Authenticate'den sonra çalışır, rol uygun değilse 403 döner.
func RequireRole(roles ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p, ok := PrincipalFrom(r.Context())
			if !ok {
				WriteError(w, http.StatusUnauthorized, "unauthorized", "Kimlik doğrulama gerekli")
				return
			}
			if !slices.Contains(roles, p.Role) {
				WriteError(w, http.StatusForbidden, "forbidden", "Bu işlem için yetkiniz yok")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}