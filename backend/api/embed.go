package api

import _ "embed"

// Spec: derlenmiş uygulamaya gömülü OpenAPI belgesi.
//
//go:embed openapi.yaml
var Spec []byte