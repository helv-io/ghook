package web

import (
	"encoding/json"
	"net/http"
	"strings"
)

func wantsJSON(r *http.Request) bool {
	if r.Header.Get("X-Requested-With") == "fetch" {
		return true
	}
	accept := r.Header.Get("Accept")
	return strings.Contains(accept, "application/json") && !strings.Contains(accept, "text/html")
}

type saveResponse struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	Field string `json:"field,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, resp saveResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(resp)
}

func writeSaveOK(w http.ResponseWriter) {
	writeJSON(w, http.StatusOK, saveResponse{OK: true})
}

func writeSaveErr(w http.ResponseWriter, msg, field string) {
	writeJSON(w, http.StatusBadRequest, saveResponse{OK: false, Error: msg, Field: field})
}

func fieldFor(msg string) string {
	m := strings.ToLower(msg)
	switch {
	case strings.Contains(m, "timezone"):
		return "timezone"
	case strings.Contains(m, "url") || strings.Contains(m, "http"):
		return "url"
	case strings.Contains(m, "regex") || strings.Contains(m, "subject"):
		return "subject"
	case strings.Contains(m, "target"):
		return "target_id"
	case strings.Contains(m, "name"):
		return "name"
	default:
		return ""
	}
}
