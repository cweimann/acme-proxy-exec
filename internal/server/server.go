package server

import (
	"encoding/json"
	"log"
	"net/http"
	"regexp"

	"github.com/andmore/acme-proxy-exec/internal/auth"
	"github.com/andmore/acme-proxy-exec/internal/execdns"
)

var safeToken = regexp.MustCompile(`^[\w.-]+$`)

// requestBody is the ACMEProxy JSON payload.
type requestBody struct {
	FQDN  string `json:"fqdn"`
	Value string `json:"value"`
}

// Server serves /present and /cleanup.
type Server struct {
	auth   *auth.Authenticator
	runner *execdns.Runner
	logger *log.Logger
	mux    *http.ServeMux
}

// New builds an HTTP server for the ACMEProxy API.
func New(a *auth.Authenticator, runner *execdns.Runner, logger *log.Logger) *Server {
	if logger == nil {
		logger = log.Default()
	}
	s := &Server{auth: a, runner: runner, logger: logger}
	mux := http.NewServeMux()
	// Path-only patterns (compatible with Go 1.19; method checked in handlers).
	mux.HandleFunc("/present", s.handlePresent)
	mux.HandleFunc("/cleanup", s.handleCleanup)
	mux.HandleFunc("/", s.handleOther)
	s.mux = mux
	return s
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.logger.Printf("HTTP %s %s %s", r.RemoteAddr, r.Method, r.URL.Path)
	s.mux.ServeHTTP(w, r)
}

func (s *Server) handleOther(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, "not found", http.StatusNotFound)
}

func (s *Server) handlePresent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.doAction(w, r, "present")
}

func (s *Server) handleCleanup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.doAction(w, r, "cleanup")
}

func (s *Server) doAction(w http.ResponseWriter, r *http.Request, action string) {
	user, pass, ok := r.BasicAuth()
	if !ok || user == "" || pass == "" {
		w.Header().Set("WWW-Authenticate", `Basic realm="acmeproxy"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var body requestBody
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&body); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	if body.FQDN == "" || body.Value == "" {
		http.Error(w, "fqdn and value are required", http.StatusBadRequest)
		return
	}
	if !safeToken.MatchString(body.FQDN) {
		http.Error(w, "invalid characters in fqdn", http.StatusBadRequest)
		return
	}
	if !safeToken.MatchString(body.Value) {
		http.Error(w, "invalid characters in value", http.StatusBadRequest)
		return
	}

	authed, domainOK := s.auth.Check(user, pass, body.FQDN)
	if !authed {
		w.Header().Set("WWW-Authenticate", `Basic realm="acmeproxy"`)
		s.logger.Printf("auth failed user=%q action=%s fqdn=%q remote=%s", user, action, body.FQDN, r.RemoteAddr)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if !domainOK {
		s.logger.Printf("domain denied user=%q action=%s fqdn=%q remote=%s", user, action, body.FQDN, r.RemoteAddr)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	s.logger.Printf("auth ok user=%q action=%s fqdn=%q remote=%s", user, action, body.FQDN, r.RemoteAddr)

	var err error
	switch action {
	case "present":
		err = s.runner.Present(r.Context(), body.FQDN, body.Value)
	case "cleanup":
		err = s.runner.Cleanup(r.Context(), body.FQDN, body.Value)
	}
	if err != nil {
		s.logger.Printf("script error user=%q action=%s fqdn=%q: %v", user, action, body.FQDN, err)
		http.Error(w, "script failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(requestBody{FQDN: body.FQDN, Value: body.Value})
}
