package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"golang.org/x/term"

	"github.com/andmore/acme-proxy-exec/internal/auth"
	"github.com/andmore/acme-proxy-exec/internal/config"
	"github.com/andmore/acme-proxy-exec/internal/execdns"
	"github.com/andmore/acme-proxy-exec/internal/server"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.SetPrefix("acme-proxy-exec: ")

	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "serve":
		err = cmdServe(os.Args[2:])
	case "hash-password":
		err = cmdHashPassword(os.Args[2:])
	case "add-user":
		err = cmdAddUser(os.Args[2:])
	case "help", "-h", "--help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		log.Fatal(err)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `Usage:
  acme-proxy-exec serve [-config path]
  acme-proxy-exec hash-password
  acme-proxy-exec add-user -user NAME -domain FQDN [-domain FQDN...] [-config path]

Environment:
  ACMEPROXY_CONFIG   default config path (default ./acmeproxy.yaml)
`)
}

func configPath(flagVal string) string {
	if flagVal != "" {
		return flagVal
	}
	if v := os.Getenv("ACMEPROXY_CONFIG"); v != "" {
		return v
	}
	return "./acmeproxy.yaml"
}

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	cfgPath := fs.String("config", "", "path to YAML config")
	_ = fs.Parse(args)

	path := configPath(*cfgPath)
	cfg, err := config.Load(path)
	if err != nil {
		return err
	}
	if err := cfg.ValidateScripts(); err != nil {
		return err
	}

	authenticator := auth.New(cfg.Users)
	runner := execdns.New(cfg.Scripts.Present, cfg.Scripts.Cleanup, cfg.Scripts.Timeout, log.Default())
	srv := server.New(authenticator, runner, log.Default())

	httpSrv := &http.Server{
		Addr:    cfg.Listen,
		Handler: srv,
	}

	reload := make(chan os.Signal, 1)
	signal.Notify(reload, syscall.SIGHUP)
	go func() {
		for range reload {
			log.Printf("SIGHUP: reloading config from %s", path)
			next, err := config.Load(path)
			if err != nil {
				log.Printf("reload failed: %v", err)
				continue
			}
			if err := next.ValidateScripts(); err != nil {
				log.Printf("reload failed: %v", err)
				continue
			}
			authenticator.Replace(next.Users)
			runner.Replace(next.Scripts.Present, next.Scripts.Cleanup, next.Scripts.Timeout)
			log.Printf("reload ok (%d users)", len(next.Users))
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	errCh := make(chan error, 1)
	go func() {
		log.Printf("listening on %s", cfg.Listen)
		if cfg.TLS != nil {
			errCh <- httpSrv.ListenAndServeTLS(cfg.TLS.Cert, cfg.TLS.Key)
		} else {
			errCh <- httpSrv.ListenAndServe()
		}
	}()

	select {
	case err := <-errCh:
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	case sig := <-stop:
		log.Printf("shutting down (%v)", sig)
		_ = httpSrv.Close()
		return nil
	}
}

func cmdHashPassword(args []string) error {
	fs := flag.NewFlagSet("hash-password", flag.ExitOnError)
	_ = fs.Parse(args)

	pass, err := readPassword("Password: ")
	if err != nil {
		return err
	}
	confirm, err := readPassword("Confirm: ")
	if err != nil {
		return err
	}
	if pass != confirm {
		return fmt.Errorf("passwords do not match")
	}
	if pass == "" {
		return fmt.Errorf("password must not be empty")
	}
	hash, err := auth.HashPassword(pass)
	if err != nil {
		return err
	}
	fmt.Println(hash)
	return nil
}

func cmdAddUser(args []string) error {
	fs := flag.NewFlagSet("add-user", flag.ExitOnError)
	cfgPath := fs.String("config", "", "path to YAML config")
	user := fs.String("user", "", "username")
	var domains multiFlag
	fs.Var(&domains, "domain", "allowed domain (repeatable)")
	_ = fs.Parse(args)

	if *user == "" {
		return fmt.Errorf("-user is required")
	}
	if len(domains) == 0 {
		return fmt.Errorf("at least one -domain is required")
	}

	path := configPath(*cfgPath)
	cfg, err := config.Load(path)
	if err != nil {
		return err
	}

	pass, err := readPassword("Password: ")
	if err != nil {
		return err
	}
	confirm, err := readPassword("Confirm: ")
	if err != nil {
		return err
	}
	if pass != confirm {
		return fmt.Errorf("passwords do not match")
	}
	if pass == "" {
		return fmt.Errorf("password must not be empty")
	}
	hash, err := auth.HashPassword(pass)
	if err != nil {
		return err
	}

	cfg.AddOrUpdateUser(*user, hash, []string(domains))
	if err := config.Save(path, cfg); err != nil {
		return err
	}
	log.Printf("updated user %q in %s (domains: %s)", *user, path, strings.Join(domains, ", "))
	log.Printf("note: concurrent edits are not coordinated; treat the config as the single source of truth")
	return nil
}

func readPassword(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		b, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", err
		}
		return string(b), nil
	}
	// Non-interactive: one line from stdin (useful for scripts/tests).
	var line string
	_, err := fmt.Fscanln(os.Stdin, &line)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	return line, nil
}

type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}
