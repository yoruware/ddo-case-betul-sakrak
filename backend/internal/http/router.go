package httpapi

import (
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yoruware/ddo-case-betul-sakrak/backend/internal/auth"
)

type Deps struct {
	Pool       *pgxpool.Pool
	Tokens     *auth.TokenService
	CORSOrigin string
}

func NewRouter(d Deps) http.Handler {
	mux := http.NewServeMux()
	authn := Authenticate(d.Tokens)

	mux.HandleFunc("GET /health", d.health)
	mux.HandleFunc("POST /api/auth/login", d.login)
	mux.HandleFunc("POST /api/auth/refresh", d.refresh)

	mux.Handle("GET /api/me", authn(http.HandlerFunc(d.me)))
	mux.Handle("GET /api/admin/ping",
		authn(RequireRole("admin")(http.HandlerFunc(d.adminPing))))

	return Cors(d.CORSOrigin, mux)
}