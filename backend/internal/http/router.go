package httpapi

import (
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yoruware/ddo-case-betul-sakrak/backend/internal/audit"
	"github.com/yoruware/ddo-case-betul-sakrak/backend/internal/auth"
	"github.com/yoruware/ddo-case-betul-sakrak/backend/internal/download"
	"github.com/yoruware/ddo-case-betul-sakrak/backend/internal/permissions"
	"github.com/yoruware/ddo-case-betul-sakrak/backend/internal/retention"
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
	Retention  *retention.Service
	Limits     upload.Limits
	Share      *ShareGuards // nil ise varsayılan sınırlarla oluşturulur
	CORSOrigin string
}

func NewRouter(d Deps) http.Handler {
	if d.Share == nil {
		d.Share = NewShareGuards()
	}
	mux := http.NewServeMux()
	authn := Authenticate(d.Tokens)
	role := func(roles ...string) func(http.HandlerFunc) http.Handler {
		return func(h http.HandlerFunc) http.Handler { return authn(RequireRole(roles...)(h)) }
	}
	user := func(h http.HandlerFunc) http.Handler { return authn(h) }
	admin := role("admin")
	auditorOnly := role("auditor", "admin")
	archivist := role("archivist", "admin")
	legalOnly := role("legal")
	records := role("archivist", "auditor", "legal", "admin")
	certs := role("archivist", "auditor", "admin")

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

	mux.Handle("POST /api/nodes/{id}/share-links", user(d.createShareLink))
	mux.Handle("GET /api/nodes/{id}/share-links", user(d.listShareLinks))
	mux.Handle("DELETE /api/share-links/{id}", user(d.revokeShareLink))
	mux.HandleFunc("GET /api/s/{token}", d.shareInfo)
	mux.HandleFunc("GET /api/s/{token}/download", d.shareDownload)
	mux.HandleFunc("POST /api/s/{token}/download", d.shareDownload)

	mux.Handle("GET /api/document-types", user(d.listDocTypes))
	mux.Handle("POST /api/document-types", archivist(d.createDocType))
	mux.Handle("PUT /api/files/{id}/retention", archivist(d.assignRetention))
	mux.Handle("GET /api/files/{id}/retention", records(d.getRetention))
	mux.Handle("POST /api/nodes/{id}/legal-holds", legalOnly(d.placeHold))
	mux.Handle("GET /api/nodes/{id}/legal-holds", records(d.listHolds))
	mux.Handle("POST /api/legal-holds/{id}/release", legalOnly(d.releaseHold))
	mux.Handle("POST /api/retention/run", archivist(d.runRetention))
	mux.Handle("GET /api/destruction-certificates", certs(d.listCertificates))
	mux.Handle("GET /api/destruction-certificates/{id}", certs(d.getCertificate))

	mux.Handle("POST /api/groups", admin(d.createGroup))
	mux.Handle("POST /api/groups/{id}/members", admin(d.addMember))
	mux.Handle("DELETE /api/groups/{id}/members/{userId}", admin(d.removeMember))

	mux.Handle("GET /api/audit", auditorOnly(d.listAudit))
	mux.Handle("GET /api/audit/verify", auditorOnly(d.verifyAudit))

	return Cors(d.CORSOrigin, mux)
}