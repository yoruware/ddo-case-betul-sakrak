package httpapi_test

import (
	"net/http/httptest"
	"strings"
	"testing"

	httpapi "github.com/yoruware/ddo-case-betul-sakrak/backend/internal/http"
)

func TestOpenAPIVeDocsSunulur(t *testing.T) {
	h := httpapi.NewRouter(httpapi.Deps{CORSOrigin: "http://localhost"})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/openapi.yaml", nil))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "openapi: 3.0.3") {
		t.Fatalf("/openapi.yaml sunulmalı: %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/docs", nil))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "SwaggerUIBundle") {
		t.Fatalf("/docs sunulmalı: %d", rec.Code)
	}
}
