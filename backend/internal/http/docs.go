package httpapi

import (
	"net/http"

	"github.com/yoruware/ddo-case-betul-sakrak/backend/api"
)

const docsHTML = `<!DOCTYPE html>
<html lang="tr"><head><meta charset="utf-8"><title>KasaDoc API</title>
<link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css"></head>
<body><div id="ui"></div>
<script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
<script>window.ui = SwaggerUIBundle({url: '/openapi.yaml', dom_id: '#ui'});</script>
</body></html>`

func (d Deps) openapiSpec(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
	_, _ = w.Write(api.Spec)
}

func (d Deps) docsPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(docsHTML))
}