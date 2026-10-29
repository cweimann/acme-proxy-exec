package auth

import (
	"strings"
	"sync"

	"golang.org/x/crypto/bcrypt"

	"github.com/andmore/acme-proxy-exec/internal/config"
)

// Authenticator verifies Basic Auth credentials and domain allowlists.
type Authenticator struct {
	mu    sync.RWMutex
	users map[string]config.User // lowercased username -> user
}

// New builds an Authenticator from cfg users.
func New(users []config.User) *Authenticator {
	a := &Authenticator{}
	a.Replace(users)
	return a
}

// Replace swaps the in-memory user set (used on config reload).
func (a *Authenticator) Replace(users []config.User) {
	m := make(map[string]config.User, len(users))
	for _, u := range users {
		m[strings.ToLower(u.Username)] = u
	}
	a.mu.Lock()
	a.users = m
	a.mu.Unlock()
}

// Check verifies username/password and that fqdn is allowed for that user.
// Returns (ok, domainAllowed). ok is false for bad credentials; domainAllowed
// is only meaningful when ok is true.
func (a *Authenticator) Check(username, password, fqdn string) (ok bool, domainAllowed bool) {
	a.mu.RLock()
	u, found := a.users[strings.ToLower(username)]
	a.mu.RUnlock()

	// Always burn a bcrypt compare to avoid timing user enumeration when missing.
	// Hash of "invalid" at default cost; only used when the user is unknown.
	hash := []byte("$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy")
	if found {
		hash = []byte(u.PasswordHash)
	}
	if bcrypt.CompareHashAndPassword(hash, []byte(password)) != nil || !found {
		return false, false
	}
	return true, DomainAllowed(fqdn, u.Domains)
}

// DomainAllowed reports whether fqdn equals or is under any allowlisted domain.
func DomainAllowed(fqdn string, domains []string) bool {
	fqdn = normalizeName(fqdn)
	for _, d := range domains {
		d = normalizeName(d)
		if fqdn == d || strings.HasSuffix(fqdn, "."+d) {
			return true
		}
	}
	return false
}

func normalizeName(name string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
}

// HashPassword returns a bcrypt hash of password.
func HashPassword(password string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
