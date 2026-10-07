package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/nickcis/own-tunnel/internal/auth"
	"github.com/nickcis/own-tunnel/internal/config"
	"github.com/nickcis/own-tunnel/internal/hostkeys"
	"github.com/nickcis/own-tunnel/internal/httpproxy"
	"github.com/nickcis/own-tunnel/internal/logging"
	"github.com/nickcis/own-tunnel/internal/registry"
	"github.com/nickcis/own-tunnel/internal/sshserver"
	"github.com/nickcis/own-tunnel/internal/tlsutil"
)

func main() {
	configPath := flag.String("config", "config.yaml", "path to YAML config")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(1)
	}

	logger := logging.New(cfg.Log.Level, cfg.Log.Format)
	logger.Info("starting own-tunnel", "domain", cfg.Domain)

	signers, err := hostkeys.LoadOrGenerate(cfg.HostKeysDir)
	if err != nil {
		logger.Error("host keys", "err", err)
		os.Exit(1)
	}

	limiter := auth.NewLimiter(cfg.Auth.MaxFailures, cfg.AuthFailureWindow(), cfg.AuthLockout())
	authenticator, err := auth.New(cfg.Users, logger, limiter)
	if err != nil {
		logger.Error("auth setup", "err", err)
		os.Exit(1)
	}

	reg := registry.New()
	sshSrv := sshserver.New(signers, authenticator, reg, cfg.Domain, cfg.Auth.MaxAuthTries, logger)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	proxy := &httpproxy.Server{
		Domain:   cfg.Domain,
		Registry: reg,
		Logger:   logger,
	}

	var wg sync.WaitGroup
	errCh := make(chan error, 3)

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := sshSrv.ListenAndServe(cfg.Listen.SSH); err != nil {
			errCh <- fmt.Errorf("ssh: %w", err)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := proxy.ListenAndServe(ctx, cfg.Listen.HTTP); err != nil {
			errCh <- fmt.Errorf("http: %w", err)
		}
	}()

	if cfg.HasTLS() {
		tlsMgr, err := tlsutil.NewManager(cfg.TLS)
		if err != nil {
			logger.Error("tls setup", "err", err)
			os.Exit(1)
		}
		proxy.TLS = tlsMgr.TLSConfig()
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := proxy.ListenAndServeTLS(ctx, cfg.Listen.HTTPS); err != nil {
				errCh <- fmt.Errorf("https: %w", err)
			}
		}()
	} else {
		logger.Warn("tls not configured; HTTPS listener disabled")
	}

	exitCode := 0
	select {
	case <-ctx.Done():
		logger.Info("shutting down")
	case err := <-errCh:
		logger.Error("server failed", "err", err)
		exitCode = 1
		stop()
	}

	_ = sshSrv.Close()
	wg.Wait()
	if exitCode != 0 {
		os.Exit(exitCode)
	}
}
