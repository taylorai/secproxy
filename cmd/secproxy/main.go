// secproxy is a credential-brokering egress proxy for sandboxed programs.
//
//	secproxy serve --config cfg.yaml            run the proxy
//	secproxy check --config cfg.yaml            validate config, print the effective policy
//	secproxy env   --config cfg.yaml [flags]    print the environment a sandboxed program should get
//	secproxy run   --config cfg.yaml -- cmd...  local convenience: serve on loopback and run cmd with that env
package main

import (
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"runtime/debug"
	"strings"
	"syscall"

	"github.com/taylorai/secproxy/internal/audit"
	"github.com/taylorai/secproxy/internal/ca"
	"github.com/taylorai/secproxy/internal/childenv"
	"github.com/taylorai/secproxy/internal/config"
	"github.com/taylorai/secproxy/internal/netguard"
	"github.com/taylorai/secproxy/internal/policy"
	"github.com/taylorai/secproxy/internal/proxy"
)

// version is set at build time with -ldflags "-X main.version=...". When it
// is not (a plain `go install module@vX.Y.Z`), Go's embedded build info
// still knows the module version, so report that.
var version = "dev"

func effectiveVersion() string {
	if version != "dev" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return version
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = cmdServe(os.Args[2:])
	case "check":
		err = cmdCheck(os.Args[2:])
	case "env":
		err = cmdEnv(os.Args[2:])
	case "run":
		err = cmdRun(os.Args[2:])
	case "version", "--version":
		fmt.Println("secproxy", effectiveVersion())
	case "-h", "--help", "help":
		usage()
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		var status *exitStatusError
		if errors.As(err, &status) {
			os.Exit(status.code)
		}
		fmt.Fprintln(os.Stderr, "secproxy:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `usage:
  secproxy serve --config cfg.yaml | --config-env VAR
  secproxy check --config cfg.yaml
  secproxy env   --config cfg.yaml [--proxy-url URL] [--ca-path PATH]
  secproxy run   --config cfg.yaml [--listen 127.0.0.1:0] -- command args...
`)
}

// configSource is the pair of flags every subcommand accepts: a file path,
// or the name of an env var holding the config (plain or base64), which is
// convenient for containers that receive everything through their
// environment.
type configSource struct {
	path string
	env  string
}

func (c *configSource) register(fs *flag.FlagSet) {
	fs.StringVar(&c.path, "config", "", "config file")
	fs.StringVar(&c.env, "config-env", "", "env var holding the config YAML (plain or base64)")
}

func (c *configSource) load() (*config.Config, error) {
	switch {
	case c.path != "" && c.env != "":
		return nil, errors.New("use --config or --config-env, not both")
	case c.path != "":
		return config.Load(c.path)
	case c.env != "":
		raw := os.Getenv(c.env)
		if raw == "" {
			return nil, fmt.Errorf("env var %s is empty or unset", c.env)
		}
		if decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(raw)); err == nil {
			raw = string(decoded)
		}
		return config.Parse([]byte(raw))
	}
	return nil, errors.New("--config or --config-env is required")
}

// loadAndCompile is shared by every subcommand that needs the real policy.
func loadAndCompile(src configSource) (*config.Config, *policy.Policy, error) {
	cfg, err := src.load()
	if err != nil {
		return nil, nil, err
	}
	cfg.FillPlaceholders()
	values, err := cfg.SecretValues()
	if err != nil {
		return nil, nil, err
	}
	pol, err := policy.Compile(cfg, values)
	if err != nil {
		return nil, nil, err
	}
	return cfg, pol, nil
}

// loadCA picks the root in the order config.CAConfig documents: a persisted
// directory, then env-supplied PEM, then a fresh in-memory root.
func loadCA(cfg *config.Config) (*ca.CA, error) {
	switch {
	case cfg.CA.PersistDir != "":
		authority, created, err := ca.Persistent(cfg.CA.PersistDir)
		if err != nil {
			return nil, err
		}
		if created {
			fmt.Fprintf(os.Stderr, "secproxy: new CA written to %s/ca.pem; trust it once and it stays valid across restarts\n", cfg.CA.PersistDir)
		}
		return authority, nil
	case cfg.CA.KeyEnv != "":
		return ca.FromPEM([]byte(os.Getenv(cfg.CA.CertEnv)), []byte(os.Getenv(cfg.CA.KeyEnv)))
	}
	return ca.NewEphemeral()
}

func cmdCheck(args []string) error {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	var src configSource
	src.register(fs)
	_ = fs.Parse(args)
	cfg, err := src.load()
	if err != nil {
		return err
	}
	cfg.FillPlaceholders()
	values, err := cfg.SecretValues()
	if err != nil {
		return err
	}
	pol, err := policy.Compile(cfg, values)
	if err != nil {
		return err
	}
	fmt.Print(pol.Summary())
	fmt.Println("config ok")
	return nil
}

func cmdEnv(args []string) error {
	fs := flag.NewFlagSet("env", flag.ExitOnError)
	var src configSource
	src.register(fs)
	proxyURL := fs.String("proxy-url", "", "connect listener URL to advertise, e.g. http://secproxy:8080 (omit behind a transparent relay)")
	caPath := fs.String("ca-path", "", "path where the sandbox will find the CA certificate")
	_ = fs.Parse(args)
	cfg, err := src.load()
	if err != nil {
		return err
	}
	cfg.FillPlaceholders()
	vars := childenv.Vars(cfg, childenv.Options{ProxyURL: *proxyURL, CAPath: *caPath})
	for _, k := range childenv.SortedKeys(vars) {
		fmt.Printf("export %s=%q\n", k, vars[k])
	}
	return nil
}

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	var src configSource
	src.register(fs)
	allowPrivate := fs.Bool("allow-private-upstreams", false, "permit dialing RFC1918/ULA addresses (metadata and loopback stay blocked)")
	_ = fs.Parse(args)
	cfg, pol, err := loadAndCompile(src)
	if err != nil {
		return err
	}
	authority, err := loadCA(cfg)
	if err != nil {
		return err
	}
	if cfg.CA.CertOut != "" {
		if err := os.WriteFile(cfg.CA.CertOut, authority.CertPEM(), 0o644); err != nil {
			return fmt.Errorf("write ca cert: %w", err)
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return serve(ctx, cfg, pol, authority, *allowPrivate)
}

// serve starts whichever listeners are configured and blocks until ctx is
// done or a listener fails.
func serve(ctx context.Context, cfg *config.Config, pol *policy.Policy, authority *ca.CA, allowPrivate bool) error {
	var transparent, connect net.Listener
	var err error
	if cfg.Listen.Transparent != "" {
		transparent, err = net.Listen("tcp", cfg.Listen.Transparent)
		if err != nil {
			return err
		}
	}
	if cfg.Listen.Connect != "" {
		connect, err = net.Listen("tcp", cfg.Listen.Connect)
		if err != nil {
			if transparent != nil {
				_ = transparent.Close()
			}
			return err
		}
	}
	return serveListeners(ctx, cfg, pol, authority, allowPrivate, transparent, connect)
}

// serveListeners runs listeners that have already been bound. Binding is
// separate because run mode must know its ephemeral port before launching
// the child.
func serveListeners(ctx context.Context, cfg *config.Config, pol *policy.Policy, authority *ca.CA, allowPrivate bool, transparent, connect net.Listener) error {
	return serveListenersWithAudit(ctx, cfg, pol, authority, allowPrivate, transparent, connect, os.Stdout)
}

func serveListenersWithAudit(ctx context.Context, cfg *config.Config, pol *policy.Policy, authority *ca.CA, allowPrivate bool, transparent, connect net.Listener, auditWriter io.Writer) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	srv := proxy.New(pol, authority, audit.New(auditWriter, cfg.RunID), &netguard.Dialer{AllowPrivate: allowPrivate})
	defer srv.Shutdown()

	errs := make(chan error, 2)
	n := 0
	if transparent != nil {
		fmt.Fprintln(os.Stderr, "secproxy: transparent listener on", transparent.Addr())
		n++
		go func() { errs <- srv.ServeTransparent(ctx, transparent) }()
	}
	if connect != nil {
		fmt.Fprintln(os.Stderr, "secproxy: connect listener on", connect.Addr())
		n++
		go func() { errs <- srv.ServeConnect(ctx, connect) }()
	}
	for i := 0; i < n; i++ {
		if err := <-errs; err != nil {
			return err
		}
	}
	return nil
}

// cmdRun is for laptops: start the connect listener on loopback, write the
// CA to a temp file, run the command with the child environment, exit with
// its status. This is cooperative (the child could ignore the proxy); it is
// a development convenience, not a sandbox.
func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	var src configSource
	src.register(fs)
	listen := fs.String("listen", "127.0.0.1:0", "loopback address for the connect listener")
	_ = fs.Parse(args)
	cmdArgs := fs.Args()
	if len(cmdArgs) == 0 {
		return errors.New("usage: secproxy run --config cfg.yaml -- command args...")
	}
	cfg, pol, err := loadAndCompile(src)
	if err != nil {
		return err
	}
	cfg.Listen = config.Listen{Connect: *listen}
	authority, err := loadCA(cfg)
	if err != nil {
		return err
	}

	listener, err := net.Listen("tcp", cfg.Listen.Connect)
	if err != nil {
		return fmt.Errorf("bind connect listener: %w", err)
	}

	caFile, err := os.CreateTemp("", "secproxy-ca-*.pem")
	if err != nil {
		_ = listener.Close()
		return fmt.Errorf("create temporary CA file: %w", err)
	}
	caPath := caFile.Name()
	defer os.Remove(caPath)
	if err := caFile.Chmod(0o600); err != nil {
		_ = caFile.Close()
		_ = listener.Close()
		return fmt.Errorf("secure temporary CA file: %w", err)
	}
	if _, err := caFile.Write(authority.CertPEM()); err != nil {
		_ = caFile.Close()
		_ = listener.Close()
		return fmt.Errorf("write temporary CA file: %w", err)
	}
	if err := caFile.Close(); err != nil {
		_ = listener.Close()
		return fmt.Errorf("close temporary CA file: %w", err)
	}

	vars := childenv.Vars(cfg, childenv.Options{
		ProxyURL: "http://" + listener.Addr().String(),
		CAPath:   caPath,
	})
	// The child must not see the variables the proxy itself reads: the real
	// secret values, the CA key, and the config (which names them).
	var hide []string
	for _, s := range cfg.Secrets {
		if s.FromEnv != "" {
			hide = append(hide, s.FromEnv)
		}
	}
	for _, name := range []string{src.env, cfg.CA.KeyEnv, cfg.CA.CertEnv} {
		if name != "" {
			hide = append(hide, name)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- serveListenersWithAudit(ctx, cfg, pol, authority, false, nil, listener, os.Stderr)
	}()
	childDone := make(chan childResult, 1)
	go func() {
		code, err := runChild(ctx, cmdArgs, vars, hide)
		childDone <- childResult{exitCode: code, err: err}
	}()

	select {
	case err := <-serveErr:
		cancel()
		<-childDone
		if err != nil {
			return fmt.Errorf("serve connect listener: %w", err)
		}
		return errors.New("connect listener stopped before child exited")
	case result := <-childDone:
		cancel()
		<-serveErr
		if result.err != nil {
			return result.err
		}
		if result.exitCode != 0 {
			return &exitStatusError{code: result.exitCode}
		}
		return nil
	}
}

type childResult struct {
	exitCode int
	err      error
}

type exitStatusError struct{ code int }

func (e *exitStatusError) Error() string { return fmt.Sprintf("child exited with status %d", e.code) }

// runChild overlays env onto the current environment, removes the
// variables in hide, and mirrors terminal signals so an interactive child
// behaves as if it were run directly.
func runChild(ctx context.Context, argv []string, env map[string]string, hide []string) (int, error) {
	if len(argv) == 0 {
		return 0, errors.New("child command is empty")
	}
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = overlayEnvironment(os.Environ(), env, hide)
	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("start child: %w", err)
	}

	signals := make(chan os.Signal, 2)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	done := make(chan struct{})
	go func() {
		defer signal.Stop(signals)
		for {
			select {
			case sig := <-signals:
				_ = cmd.Process.Signal(sig)
			case <-done:
				return
			}
		}
	}()

	err := cmd.Wait()
	close(done)
	if err == nil {
		return 0, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		if status, ok := exitErr.Sys().(syscall.WaitStatus); ok && status.Signaled() {
			return 128 + int(status.Signal()), nil
		}
		return exitErr.ExitCode(), nil
	}
	return 0, fmt.Errorf("wait for child: %w", err)
}

func overlayEnvironment(base []string, overrides map[string]string, hide []string) []string {
	hidden := map[string]bool{}
	for _, name := range hide {
		hidden[name] = true
	}
	out := make([]string, 0, len(base)+len(overrides))
	for _, entry := range base {
		name, _, ok := strings.Cut(entry, "=")
		if _, overridden := overrides[name]; ok && overridden {
			continue
		}
		if ok && hidden[name] {
			continue
		}
		out = append(out, entry)
	}
	for _, name := range childenv.SortedKeys(overrides) {
		out = append(out, name+"="+overrides[name])
	}
	return out
}
