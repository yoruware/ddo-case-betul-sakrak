package httpapi

import (
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yoruware/ddo-case-betul-sakrak/backend/internal/auth"
	"github.com/yoruware/ddo-case-betul-sakrak/backend/internal/permissions"
)

type Deps struct {
	Pool       *pgxpool.Pool
	Tokens     *auth.TokenService
	Perms      *permissions.Service
	CORSOrigin string
}

func NewRouter(d Deps) http.Handler {
	mux := http.NewServeMux()
	authn := Authenticate(d.Tokens)
	user := func(h http.HandlerFunc) http.Handler { return authn(h) }
	admin := func(h http.HandlerFunc) http.Handler { return authn(RequireRole("admin")(h)) }

	mux.HandleFunc("GET /health", d.health)
	mux.HandleFunc("POST /api/auth/login", d.login)
	mux.HandleFunc("POST /api/auth/refresh", d.refresh)

	mux.Handle("GET /api/me", user(d.me))
	mux.Handle("GET /api/admin/ping", admin(d.adminPing))

	mux.Handle("POST /api/nodes", user(d.createNode))
	mux.Handle("GET /api/nodes", user(d.listNodes))
	mux.Handle("POST /api/nodes/{id}/acl", user(d.setACL))
	mux.Handle("DELETE /api/nodes/{id}/acl/{entryId}", user(d.revokeACL))
	mux.Handle("GET /api/nodes/{id}/effective-permissions", user(d.effective))

	mux.Handle("POST /api/groups", admin(d.createGroup))
	mux.Handle("POST /api/groups/{id}/members", admin(d.addMember))
	mux.Handle("DELETE /api/groups/{id}/members/{userId}", admin(d.removeMember))

	return Cors(d.CORSOrigin, mux)
}