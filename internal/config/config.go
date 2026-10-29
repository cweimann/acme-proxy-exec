package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the on-disk YAML configuration for acme-proxy-exec.
type Config struct {
	Listen  string  `yaml:"listen"`
	TLS     *TLS    `yaml:"tls,omitempty"`
	Scripts Scripts `yaml:"scripts"`
	Users   []User  `yaml:"users"`
}

// TLS holds optional static certificate paths for the proxy itself.
type TLS struct {
	Cert string `yaml:"cert"`
	Key  string `yaml:"key"`
}

// Scripts configures the present/cleanup executables.
type Scripts struct {
	Present string        `yaml:"present"`
	Cleanup string        `yaml:"cleanup"`
	Timeout time.Duration `yaml:"-"`
	// TimeoutRaw accepts Go duration strings (e.g. "30s") in YAML.
	TimeoutRaw string `yaml:"timeout"`
}

// User is an authenticated ACMEProxy client with domain allowlist.
type User struct {
	Username     string   `yaml:"username"`
	PasswordHash string   `yaml:"password_hash"`
	Domains      []string `yaml:"domains"`
}

// Load reads and validates a config file from path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Validate checks required fields and normalizes defaults.
func (c *Config) Validate() error {
	if c.Listen == "" {
		c.Listen = ":9090"
	}
	if c.Scripts.TimeoutRaw != "" {
		d, err := time.ParseDuration(c.Scripts.TimeoutRaw)
		if err != nil {
			return fmt.Errorf("scripts.timeout: %w", err)
		}
		c.Scripts.Timeout = d
	}
	if c.Scripts.Timeout <= 0 {
		c.Scripts.Timeout = 30 * time.Second
		c.Scripts.TimeoutRaw = "30s"
	}
	if c.Scripts.Present == "" {
		return fmt.Errorf("scripts.present is required")
	}
	if !filepath.IsAbs(c.Scripts.Present) {
		return fmt.Errorf("scripts.present must be an absolute path")
	}
	if c.Scripts.Cleanup == "" {
		return fmt.Errorf("scripts.cleanup is required")
	}
	if !filepath.IsAbs(c.Scripts.Cleanup) {
		return fmt.Errorf("scripts.cleanup must be an absolute path")
	}
	if c.TLS != nil {
		if c.TLS.Cert == "" || c.TLS.Key == "" {
			return fmt.Errorf("tls.cert and tls.key are both required when tls is set")
		}
		if !filepath.IsAbs(c.TLS.Cert) {
			return fmt.Errorf("tls.cert must be an absolute path")
		}
		if !filepath.IsAbs(c.TLS.Key) {
			return fmt.Errorf("tls.key must be an absolute path")
		}
	}
	seen := make(map[string]struct{})
	for i := range c.Users {
		u := &c.Users[i]
		if u.Username == "" {
			return fmt.Errorf("users[%d]: username is required", i)
		}
		if u.PasswordHash == "" {
			return fmt.Errorf("users[%d]: password_hash is required", i)
		}
		if len(u.Domains) == 0 {
			return fmt.Errorf("users[%d]: at least one domain is required", i)
		}
		key := strings.ToLower(u.Username)
		if _, ok := seen[key]; ok {
			return fmt.Errorf("duplicate username %q", u.Username)
		}
		seen[key] = struct{}{}
		for j, d := range u.Domains {
			d = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
			if d == "" {
				return fmt.Errorf("users[%d].domains[%d]: empty domain", i, j)
			}
			u.Domains[j] = d
		}
	}
	return nil
}

// ValidateScripts ensures present/cleanup exist and are executable (serve/reload).
func (c *Config) ValidateScripts() error {
	if err := checkScript("present", c.Scripts.Present); err != nil {
		return err
	}
	return checkScript("cleanup", c.Scripts.Cleanup)
}

func checkScript(name, path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("scripts.%s: %w", name, err)
	}
	if info.IsDir() {
		return fmt.Errorf("scripts.%s is a directory", name)
	}
	if info.Mode()&0o111 == 0 {
		return fmt.Errorf("scripts.%s is not executable", name)
	}
	return nil
}

// Save writes cfg to path with mode 0600.
// Concurrent edits are not coordinated; treat the file as the single source of truth.
func Save(path string, cfg *Config) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	if cfg.Scripts.TimeoutRaw == "" && cfg.Scripts.Timeout > 0 {
		cfg.Scripts.TimeoutRaw = cfg.Scripts.Timeout.String()
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("replace config: %w", err)
	}
	return nil
}

// AddOrUpdateUser sets password hash and merges domains for username.
func (c *Config) AddOrUpdateUser(username, passwordHash string, domains []string) {
	key := strings.ToLower(username)
	for i := range c.Users {
		if strings.ToLower(c.Users[i].Username) == key {
			c.Users[i].PasswordHash = passwordHash
			c.Users[i].Domains = mergeDomains(c.Users[i].Domains, domains)
			return
		}
	}
	c.Users = append(c.Users, User{
		Username:     username,
		PasswordHash: passwordHash,
		Domains:      normalizeDomains(domains),
	})
}

func mergeDomains(existing, added []string) []string {
	set := make(map[string]struct{})
	out := make([]string, 0, len(existing)+len(added))
	for _, d := range append(existing, added...) {
		d = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
		if d == "" {
			continue
		}
		if _, ok := set[d]; ok {
			continue
		}
		set[d] = struct{}{}
		out = append(out, d)
	}
	return out
}

func normalizeDomains(domains []string) []string {
	return mergeDomains(nil, domains)
}
