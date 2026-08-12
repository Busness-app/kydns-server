// Package app wires the process together. It is the only place that knows
// about every other package.
package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"github.com/yoshiofthewire/kydns-server/internal/adminapi"
	"github.com/yoshiofthewire/kydns-server/internal/auth"
	"github.com/yoshiofthewire/kydns-server/internal/config"
	"github.com/yoshiofthewire/kydns-server/internal/discovery"
	"github.com/yoshiofthewire/kydns-server/internal/discovery/dhcp"
	"github.com/yoshiofthewire/kydns-server/internal/dnsserver"
	"github.com/yoshiofthewire/kydns-server/internal/health"
	"github.com/yoshiofthewire/kydns-server/internal/registry"
	"github.com/yoshiofthewire/kydns-server/internal/store"
	"github.com/yoshiofthewire/kydns-server/internal/upstream"
	"github.com/yoshiofthewire/kydns-server/internal/web"
	"github.com/yoshiofthewire/kydns-server/internal/zone"
)

// Serve runs the DNS and admin listeners until ctx is cancelled.
func Serve(ctx context.Context, cfgPath string, logger *slog.Logger) error {
	if logger == nil {
		logger = slog.Default()
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err // fail fast: never run half-configured
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}
	st, err := store.Open(filepath.Join(cfg.DataDir, "kydns.db"))
	if err != nil {
		return err
	}
	defer st.Close()

	reverse := make([]netip.Prefix, 0, len(cfg.DNS.ReverseZones))
	for _, z := range cfg.DNS.ReverseZones {
		p, err := netip.ParsePrefix(z)
		if err != nil {
			return err
		}
		reverse = append(reverse, p.Masked())
	}

	// Declared before the holder so the source closure captures the variable;
	// it is assigned below, once the holder exists to rebuild.
	var poller *discovery.Poller

	holder := zone.NewHolder(func() (zone.Input, error) {
		views, err := st.Views()
		if err != nil {
			return zone.Input{}, err
		}
		svcs, err := st.Services()
		if err != nil {
			return zone.Input{}, err
		}
		recs, err := st.Records()
		if err != nil {
			return zone.Input{}, err
		}
		var leases []zone.Lease
		if poller != nil {
			for _, l := range poller.Leases() {
				leases = append(leases, zone.Lease{Hostname: l.Hostname, Address: l.IP})
			}
		}
		return zone.Input{
			Views: views, Services: svcs, Records: recs, Leases: leases,
			Zone: cfg.PrivateFQDN(), ReverseZones: reverse,
		}, nil
	})
	if err := holder.Rebuild(); err != nil {
		return fmt.Errorf("initial snapshot: %w", err)
	}

	reg := registry.New(st, cfg.PrivateFQDN(), func() error {
		if err := holder.Rebuild(); err != nil {
			// The write is already committed; the old snapshot keeps serving.
			logger.Error("snapshot rebuild failed, still serving the previous snapshot", "error", err)
			return err
		}
		return nil
	})

	if cfg.Discovery.DHCPLeaseFile != "" {
		poller = discovery.NewPoller(
			&dhcp.DnsmasqSource{Path: cfg.Discovery.DHCPLeaseFile},
			time.Duration(cfg.Discovery.Interval)*time.Second,
			func() {
				if err := holder.Rebuild(); err != nil {
					logger.Error("rebuild after lease change failed", "error", err)
				}
			}, logger)
	}

	if err := bootstrapToken(reg, cfg.DataDir, logger); err != nil {
		return err
	}

	allowed, err := cfg.EffectiveAllowQuery()
	if err != nil {
		return err
	}
	acl := dnsserver.NewACL(allowed)
	logger.Info("query acl", "ranges", cfg.DNS.AllowQuery, "allow_tailscale", cfg.DNS.AllowTailscale)
	warnUnreachableViews(st, cfg, logger)

	cache := dnsserver.NewCache(cfg.DNS.CacheEntries, cfg.DNS.CacheMinTTL, cfg.DNS.CacheMaxTTL, cfg.DNS.NegativeMaxTTL)
	ups, err := upstream.NewAll(cfg.DNS.Upstreams, 2*time.Second)
	if err != nil {
		return err
	}
	for _, u := range ups {
		if !u.Secure() {
			logger.Warn("upstream is unencrypted; answers from it cannot be authenticated",
				"upstream", u.String(),
				"fix", "use a tls:// or https:// upstream in dns.upstreams")
		}
	}
	fwd := dnsserver.NewForwarder(ups, 2*time.Second, cache)

	dnsSrv := dnsserver.New(dnsserver.Options{
		Holder: holder, ACL: acl,
		Auth: &dnsserver.Authoritative{
			Zone: cfg.PrivateFQDN(), TTL: uint32(cfg.DNS.TTL), ReverseZones: reverse,
		},
		Forwarder:   fwd,
		LogQueries:  cfg.DNS.LogQueries,
		LogClientIP: cfg.DNS.LogClientIP,
		Logger:      logger,
	})

	checker := health.NewChecker(reg,
		time.Duration(cfg.Health.Interval)*time.Second,
		time.Duration(cfg.Health.Timeout)*time.Second,
		cfg.Health.Workers, logger)

	leaseFn := func() []dhcp.Lease {
		if poller == nil {
			return nil
		}
		return poller.Leases()
	}

	// One mux serves both transports: the API owns /api/v1/... and the web
	// server owns everything else.
	api := adminapi.NewAPI(reg, acl, cache).WithProviders(leaseFn, checker.Statuses)
	mux := http.NewServeMux()
	api.Routes(mux)

	setupToken, err := ensureSetupToken(st, cfg.DataDir, logger)
	if err != nil {
		return err
	}
	web.New(web.Options{
		Store: st, Registry: reg, API: api, Config: cfg,
		Sessions:       auth.NewSessions(time.Hour, 12*time.Hour),
		Backoff:        auth.NewBackoff(),
		ACL:            acl,
		Cache:          cache,
		AllowTailscale: cfg.DNS.AllowTailscale,
		Upstreams:      fwd.Status,
		SetupToken:     setupToken,
		Logger:         logger,
		Health:         checker.Statuses,
		Leases: func() func() []dhcp.Lease {
			if poller == nil {
				return nil // the screen renders "discovery is off" rather than empty
			}
			return leaseFn
		}(),
	}).Routes(mux)

	adminSrv := &http.Server{
		Addr:              cfg.Admin.Listen,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	errs := make(chan error, 2)
	go func() { errs <- dnsSrv.ListenAndServe(cfg.DNS.Listen) }()
	go func() {
		if err := adminSrv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			errs <- err
		}
	}()
	if poller != nil {
		go poller.Run(ctx)
	}
	go checker.Run(ctx)
	logger.Info("kydns started",
		"dns", cfg.DNS.Listen, "admin", cfg.Admin.Listen, "zone", cfg.PrivateFQDN())

	select {
	case err := <-errs:
		return err
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return errors.Join(dnsSrv.Shutdown(shutdown), adminSrv.Shutdown(shutdown))
}

// bootstrapToken mints a first API token when none exist and writes it to the
// data dir, so a fresh install is usable without a chicken-and-egg problem.
// Plan 2 replaces this with the /setup flow.
func bootstrapToken(reg *registry.Registry, dataDir string, logger *slog.Logger) error {
	toks, err := reg.Tokens()
	if err != nil {
		return err
	}
	if len(toks) > 0 {
		return nil // already minted; a restart must not invalidate it
	}
	plaintext, err := reg.CreateToken("bootstrap")
	if err != nil {
		return err
	}
	path := filepath.Join(dataDir, "bootstrap-token")
	if err := os.WriteFile(path, []byte(plaintext+"\n"), 0o600); err != nil {
		return err
	}
	logger.Info("wrote bootstrap API token", "path", path)
	return nil
}

// warnUnreachableViews implements banner condition 2: a view whose CIDRs the
// ACL rejects can never match.
func warnUnreachableViews(st *store.Store, cfg *config.Config, logger *slog.Logger) {
	if cfg.DNS.AllowTailscale {
		return
	}
	cgnat := netip.MustParsePrefix(config.TailscaleCGNAT)
	views, err := st.Views()
	if err != nil {
		return
	}
	for _, v := range views {
		for _, c := range v.Subnets {
			p, err := netip.ParsePrefix(c)
			if err != nil || !cgnat.Overlaps(p) {
				continue
			}
			logger.Warn("view can never match: its subnet is refused by the query ACL",
				"view", v.Name, "subnet", c,
				"fix", "set allow_tailscale: true in the config file and restart")
		}
	}
}

// ensureSetupToken mints the one-time token that gates /setup, unless an admin
// already exists. It is logged and written to the data dir, because the
// operator needs it from a terminal before any UI is reachable.
func ensureSetupToken(st *store.Store, dataDir string, logger *slog.Logger) (string, error) {
	has, err := st.HasAdmin()
	if err != nil {
		return "", err
	}
	if has {
		return "", nil // no admin creation possible, so no token needed
	}
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	token := hex.EncodeToString(buf)
	path := filepath.Join(dataDir, "setup-token")
	if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		return "", err
	}
	logger.Info("no admin account yet: open the web UI and use this setup token",
		"token", token, "path", path)
	return token, nil
}
