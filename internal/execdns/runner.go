package execdns

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os/exec"
	"sync"
	"time"
)

// Runner executes present/cleanup scripts with FQDN and value as argv.
type Runner struct {
	mu      sync.RWMutex
	present string
	cleanup string
	timeout time.Duration
	logger  *log.Logger
}

// New creates a Runner.
func New(present, cleanup string, timeout time.Duration, logger *log.Logger) *Runner {
	if logger == nil {
		logger = log.Default()
	}
	return &Runner{
		present: present,
		cleanup: cleanup,
		timeout: timeout,
		logger:  logger,
	}
}

// Replace updates script paths and timeout (config reload).
func (r *Runner) Replace(present, cleanup string, timeout time.Duration) {
	r.mu.Lock()
	r.present = present
	r.cleanup = cleanup
	r.timeout = timeout
	r.mu.Unlock()
}

// Present runs the present script as: present fqdn value
func (r *Runner) Present(ctx context.Context, fqdn, value string) error {
	return r.run(ctx, "present", fqdn, value)
}

// Cleanup runs the cleanup script as: cleanup fqdn value
func (r *Runner) Cleanup(ctx context.Context, fqdn, value string) error {
	return r.run(ctx, "cleanup", fqdn, value)
}

func (r *Runner) run(ctx context.Context, action, fqdn, value string) error {
	r.mu.RLock()
	path := r.present
	if action == "cleanup" {
		path = r.cleanup
	}
	timeout := r.timeout
	r.mu.RUnlock()

	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	cmd := exec.CommandContext(ctx, path, fqdn, value)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	exitCode := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			exitCode = ee.ExitCode()
		} else if ctx.Err() != nil {
			r.logger.Printf("script %s timed out or canceled for fqdn=%q: %v", action, fqdn, ctx.Err())
			return fmt.Errorf("%s script timed out or canceled", action)
		} else {
			r.logger.Printf("script %s failed to start for fqdn=%q: %v", action, fqdn, err)
			return fmt.Errorf("%s script failed to start: %w", action, err)
		}
	}

	if out := bytes.TrimSpace(stdout.Bytes()); len(out) > 0 {
		r.logger.Printf("script %s stdout fqdn=%q: %s", action, fqdn, out)
	}
	if out := bytes.TrimSpace(stderr.Bytes()); len(out) > 0 {
		r.logger.Printf("script %s stderr fqdn=%q: %s", action, fqdn, out)
	}

	if exitCode != 0 {
		r.logger.Printf("script %s exit=%d fqdn=%q", action, exitCode, fqdn)
		return fmt.Errorf("%s script exited %d", action, exitCode)
	}
	r.logger.Printf("script %s ok fqdn=%q", action, fqdn)
	return nil
}
