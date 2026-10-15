package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const apiBase = "https://sendtim.com/api/v1"

var (
	sendtimClient       = &http.Client{Timeout: 10 * time.Second}
	emailPattern        = regexp.MustCompile(`^\S+@\S+\.\S+$`)
	uuidPattern         = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	propertyNamePattern = regexp.MustCompile(`^[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,63}$`)
	consentSources      = map[string]bool{"import": true, "form": true, "api": true, "manual": true, "double_opt_in": true, "unknown": true}
	limiter             = newRateLimiter(5, 10*time.Minute)
)

type contactSignup struct {
	Email            string         `json:"email"`
	FirstName        *string        `json:"firstName,omitempty"`
	LastName         *string        `json:"lastName,omitempty"`
	Company          *string        `json:"company,omitempty"`
	Source           *string        `json:"source,omitempty"`
	CustomProperties map[string]any `json:"customProperties,omitempty"`
	ListIDs          []string       `json:"listIds,omitempty"`
	ConsentGiven     *bool          `json:"consentGiven,omitempty"`
	ConsentSource    *string        `json:"consentSource,omitempty"`
}

type rateEntry struct {
	count   int
	resetAt time.Time
}

type rateLimiter struct {
	mu      sync.Mutex
	entries map[string]rateEntry
	max     int
	window  time.Duration
}

func newRateLimiter(max int, window time.Duration) *rateLimiter {
	return &rateLimiter{entries: make(map[string]rateEntry), max: max, window: window}
}

func (l *rateLimiter) allow(key string) (bool, int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	entry, ok := l.entries[key]
	if !ok || !entry.resetAt.After(now) {
		l.entries[key] = rateEntry{count: 1, resetAt: now.Add(l.window)}
		return true, 0
	}
	if entry.count >= l.max {
		retryAfter := (time.Until(entry.resetAt) + time.Second - 1) / time.Second
		return false, int(retryAfter)
	}
	entry.count++
	l.entries[key] = entry
	return true, 0
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": message}})
}

func sendtim(w http.ResponseWriter, path, method string, body any) {
	key := os.Getenv("SENDTIM_API_KEY")
	if key == "" {
		writeError(w, http.StatusInternalServerError, "configuration_error", "SENDTIM_API_KEY is required.")
		return
	}

	var input io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "internal_error", "Could not encode request.")
			return
		}
		input = bytes.NewReader(encoded)
	}

	req, err := http.NewRequest(method, apiBase+path, input)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "Could not create request.")
		return
	}
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := sendtimClient.Do(req)
	if err != nil {
		writeError(w, http.StatusBadGateway, "upstream_unavailable", "Sendtim could not be reached.")
		return
	}
	defer resp.Body.Close()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, io.LimitReader(resp.Body, 1<<20))
}

func sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	if configured := os.Getenv("APP_ORIGIN"); configured != "" {
		return origin == configured
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return origin == scheme+"://"+r.Host
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func validOptionalString(value *string, maxLength int) bool {
	return value == nil || len(strings.TrimSpace(*value)) <= maxLength
}

func contacts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Use POST.")
		return
	}
	if !sameOrigin(r) {
		writeError(w, http.StatusForbidden, "origin_not_allowed", "Origin not allowed.")
		return
	}
	if allowed, retryAfter := limiter.allow(clientIP(r)); !allowed {
		w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
		writeError(w, http.StatusTooManyRequests, "rate_limited", "Too many requests.")
		return
	}
	if strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0]) != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type must be application/json.")
		return
	}

	var signup contactSignup
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 10_000))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&signup); err != nil {
		writeError(w, http.StatusBadRequest, "validation_failed", "Body must be a valid signup JSON object.")
		return
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		writeError(w, http.StatusBadRequest, "validation_failed", "Body must contain one JSON object.")
		return
	}

	signup.Email = strings.ToLower(strings.TrimSpace(signup.Email))
	if !emailPattern.MatchString(signup.Email) || len(signup.Email) > 254 {
		writeError(w, http.StatusBadRequest, "validation_failed", "Enter a valid email address.")
		return
	}
	if !validOptionalString(signup.FirstName, 120) || !validOptionalString(signup.LastName, 120) ||
		!validOptionalString(signup.Company, 200) || !validOptionalString(signup.Source, 64) {
		writeError(w, http.StatusBadRequest, "validation_failed", "A contact field is too long.")
		return
	}

	for key, value := range signup.CustomProperties {
		validValue := value == nil
		switch typed := value.(type) {
		case string:
			validValue = len(typed) <= 1000
		case float64, bool:
			validValue = true
		}
		if !propertyNamePattern.MatchString(key) || !validValue {
			writeError(w, http.StatusBadRequest, "validation_failed", "customProperties contains an invalid key or value.")
			return
		}
	}
	if len(signup.ListIDs) > 50 {
		writeError(w, http.StatusBadRequest, "validation_failed", "listIds must contain at most 50 UUIDs.")
		return
	}
	for _, id := range signup.ListIDs {
		if !uuidPattern.MatchString(id) {
			writeError(w, http.StatusBadRequest, "validation_failed", "listIds must contain at most 50 UUIDs.")
			return
		}
	}
	if signup.ConsentSource != nil && !consentSources[*signup.ConsentSource] {
		writeError(w, http.StatusBadRequest, "validation_failed", "consentSource is invalid.")
		return
	}

	for _, value := range []*string{signup.FirstName, signup.LastName, signup.Company, signup.Source} {
		if value != nil {
			*value = strings.TrimSpace(*value)
		}
	}
	sendtim(w, "/contacts", http.MethodPost, signup)
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Use GET.")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "service": "sendtim-go-example"})
	})
	mux.HandleFunc("/api/contacts", contacts)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	server := &http.Server{
		Addr:              ":" + port,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	log.Printf("Sendtim Go example listening on http://localhost:%s", port)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
