package auth

import (
	"testing"

	"github.com/andmore/acme-proxy-exec/internal/config"
)

func TestDomainAllowed(t *testing.T) {
	domains := []string{"bob.example.com", "other.example.com."}

	cases := []struct {
		fqdn string
		want bool
	}{
		{"bob.example.com", true},
		{"bob.example.com.", true},
		{"_acme-challenge.bob.example.com", true},
		{"_acme-challenge.bob.example.com.", true},
		{"sub.bob.example.com", true},
		{"other.example.com", true},
		{"_acme-challenge.other.example.com", true},
		{"example.com", false},
		{"notbob.example.com", false},
		{"bob.example.com.evil.com", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := DomainAllowed(tc.fqdn, domains); got != tc.want {
			t.Errorf("DomainAllowed(%q) = %v, want %v", tc.fqdn, got, tc.want)
		}
	}
}

func TestCheck(t *testing.T) {
	hash, err := HashPassword("s3cret")
	if err != nil {
		t.Fatal(err)
	}
	a := New([]config.User{{
		Username:     "bob",
		PasswordHash: hash,
		Domains:      []string{"bob.example.com"},
	}})

	ok, domainOK := a.Check("bob", "s3cret", "_acme-challenge.bob.example.com")
	if !ok || !domainOK {
		t.Fatalf("expected auth+domain ok, got ok=%v domainOK=%v", ok, domainOK)
	}

	ok, domainOK = a.Check("bob", "s3cret", "_acme-challenge.other.example.com")
	if !ok || domainOK {
		t.Fatalf("expected auth ok but domain denied, got ok=%v domainOK=%v", ok, domainOK)
	}

	ok, _ = a.Check("bob", "wrong", "_acme-challenge.bob.example.com")
	if ok {
		t.Fatal("expected auth failure for bad password")
	}

	ok, _ = a.Check("nobody", "s3cret", "_acme-challenge.bob.example.com")
	if ok {
		t.Fatal("expected auth failure for unknown user")
	}
}
