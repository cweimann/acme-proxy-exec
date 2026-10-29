package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadAndSave(t *testing.T) {
	dir := t.TempDir()
	present := filepath.Join(dir, "present")
	cleanup := filepath.Join(dir, "cleanup")
	for _, p := range []string{present, cleanup} {
		if err := os.WriteFile(p, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	path := filepath.Join(dir, "acmeproxy.yaml")
	src := []byte(`
listen: ":9090"
scripts:
  present: ` + present + `
  cleanup: ` + cleanup + `
  timeout: 15s
users:
  - username: bob
    password_hash: "$2a$10$abc"
    domains:
      - Bob.Example.COM.
`)
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.ValidateScripts(); err != nil {
		t.Fatal(err)
	}
	if cfg.Scripts.Timeout != 15*time.Second {
		t.Fatalf("timeout = %v", cfg.Scripts.Timeout)
	}
	if cfg.Users[0].Domains[0] != "bob.example.com" {
		t.Fatalf("domain normalize = %q", cfg.Users[0].Domains[0])
	}

	cfg.AddOrUpdateUser("bob", "$2a$10$new", []string{"extra.example.com"})
	if err := Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	cfg2, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg2.Users[0].PasswordHash != "$2a$10$new" {
		t.Fatalf("hash not updated: %s", cfg2.Users[0].PasswordHash)
	}
	if len(cfg2.Users[0].Domains) != 2 {
		t.Fatalf("domains = %v", cfg2.Users[0].Domains)
	}
}
