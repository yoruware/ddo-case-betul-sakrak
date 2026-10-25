package httpapi

import (
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yoruware/ddo-case-betul-sakrak/backend/internal/audit"
	"github.com/yoruware/ddo-case-betul-sakrak/backend/internal/auth"
	"github.com/yoruware/ddo-case-betul-sakrak/backend/internal/download"
	"github.com/yoruware/ddo-case-betul-sakrak/backend/internal/permissions"
	"github.com/yoruware/ddo-case-betul-sakrak/backend/internal/storage"
	"github.com/yoruware/ddo-case-betul-sakrak/backend/internal/upload"
)

type Deps struct {
	Pool       *pgxpool.Pool
	Tokens     *auth.TokenService
	Perms      *permissions.Service
	Audit      *audit.Service
	Store      *storage.Store
	Signer     *download.Signer
	Limits     upload.Limits
	CORSOrigin string
}

func NewRouter(d Deps) http.Handler {
	mux := http.NewServeMux()
	authn := Authenticate(d.Tokens)
	user := func(h http.HandlerFunc) http.Handler { return authn(h) }
	admin := func(h http.HandlerFunc) http.Handler { return authn(RequireRole("admin")(h)) }
	auditorOnly := func(h http.HandlerFunc) http.Handler { return authn(RequireRole("auditor", "admin")(h)) }

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

	mux.Handle("POST /api/nodes/{id}/files", user(d.uploadFile))
	mux.Handle("POST /api/files/{id}/download-link", user(d.downloadLink))
	mux.HandleFunc("GET /api/download/{id}", d.downloadFile)
	mux.Handle("GET /api/quarantine", auditorOnly(d.listQuarantine))

	mux.Handle("POST /api/groups", admin(d.createGroup))
	mux.Handle("POST /api/groups/{id}/members", admin(d.addMember))
	mux.Handle("DELETE /api/groups/{id}/members/{userId}", admin(d.removeMember))

	mux.Handle("GET /api/audit", auditorOnly(d.listAudit))
	mux.Handle("GET /api/audit/verify", auditorOnly(d.verifyAudit))

	return Cors(d.CORSOrigin, mux)
}
