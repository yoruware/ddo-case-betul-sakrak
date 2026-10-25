package httpapi

import (
	"net/http"
	"strconv"
)

func (d Deps) verifyAudit(w http.ResponseWriter, r *http.Request) {
	res, err := d.Audit.Verify(r.Context())
	if err != nil {
		internalError(w, "denetim zinciri doğrulanamadı", err)
		return
	}
	WriteJSON(w, http.StatusOK, res)
}

func (d Deps) listAudit(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var after int64
	if v := q.Get("after"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 0 {
			WriteError(w, http.StatusBadRequest, "invalid_request", "after geçersiz")
			return
		}
		after = n
	}
	limit := 50
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 200 {
			WriteError(w, http.StatusBadRequest, "invalid_request", "limit 1-200 arasında olmalı")
			return
		}
		limit = n
	}
	items, err := d.Audit.List(r.Context(), after, limit+1)
	if err != nil {
		internalError(w, "denetim kayıtları okunamadı", err)
		return
	}
	var next *int64
	if len(items) > limit {
		items = items[:limit]
		last := items[limit-1].Seq
		next = &last
	}
	WriteJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": next})
}