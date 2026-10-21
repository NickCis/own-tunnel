package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
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
	"github.com/nickcis/own-tunnel/internal/wsgateway"
)

func websocketReservedTunnelName(cfg *config.Config) string {
	if cfg == nil || !cfg.WebSocketEnabled() {
		return ""
	}
	host := strings.ToLower(strings.TrimSpace(cfg.WebSocket.Host))
	domain := strings.ToLower(strings.TrimSpace(cfg.Domain))
	if host == "" || domain == "" || host == domain {
		return ""
	}
	name, ok := strings.CutSuffix(host, "."+domain)
	if !ok || name == "" {
		return ""
	}
	return name
}

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
	sshSrv.HasTLS = cfg.HasTLS()
	if name := websocketReservedTunnelName(cfg); name != "" {
		sshSrv.ReservedNames = map[string]struct{}{name: {}}
		logger.Info("websocket control host reserves tunnel name", "name", name)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	proxy := &httpproxy.Server{
		Domain:   cfg.Domain,
		Registry: reg,
		Logger:   logger,
	}

	var wsGW *wsgateway.Gateway
	if cfg.WebSocketEnabled() {
		wsGW = wsgateway.New(sshSrv, cfg.WebSocket.Path, logger)
		proxy.ControlHost = cfg.WebSocket.Host
		proxy.ControlPath = cfg.WebSocket.Path
		proxy.ControlHandler = wsGW
		proxy.ControlRequireTLS = !cfg.WebSocket.AllowHTTP
		logger.Info("websocket ssh gateway enabled",
			"host", cfg.WebSocket.Host,
			"path", cfg.WebSocket.Path,
			"require_tls", proxy.ControlRequireTLS,
		)
		if !cfg.HasTLS() && !cfg.WebSocket.AllowHTTP {
			logger.Warn("websocket ssh gateway requires TLS but no TLS certificates are configured; endpoint will be unreachable")
		}
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
	if wsGW != nil {
		_ = wsGW.Close()
	}
	wg.Wait()
	if exitCode != 0 {
		os.Exit(exitCode)
	}
}
