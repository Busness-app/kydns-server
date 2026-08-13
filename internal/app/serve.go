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
	"slices"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/yoshiofthewire/kydns-server/internal/adminapi"
	"github.com/yoshiofthewire/kydns-server/internal/auth"
	"github.com/yoshiofthewire/kydns-server/internal/config"
	"github.com/yoshiofthewire/kydns-server/internal/discovery"
	"github.com/yoshiofthewire/kydns-server/internal/discovery/dhcp"
	"github.com/yoshiofthewire/kydns-server/internal/dnsserver"
	"github.com/yoshiofthewire/kydns-server/internal/health"
	"github.com/yoshiofthewire/kydns-server/internal/policy"
	"github.com/yoshiofthewire/kydns-server/internal/registry"
	"github.com/yoshiofthewire/kydns-server/internal/settings"
	"github.com/yoshiofthewire/kydns-server/internal/store"
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

	boot, err := ensureSettings(st, cfg, logger)
	if err != nil {
		return err
	}
	settingsHolder := settings.NewHolder(func() (store.Settings, error) {
		v, ok, err := st.Settings()
		if err != nil {
			return v, err
		}
		if !ok {
			return v, errors.New("settings row vanished")
		}
		return v, nil
	})
	if err := settingsHolder.Rebuild(); err != nil {
		return fmt.Errorf("initial settings: %w", err)
	}
	snap := settingsHolder.Current()

	// The boot value only seeds the zone. It is editable at runtime, so every
	// component that needs it is told again by Apply on each settings change.
	privateFQDN := dns.Fqdn(strings.ToLower(boot.PrivateDomain))

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
		cur := settingsHolder.Current()
		return zone.Input{
			Views: views, Services: svcs, Records: recs, Leases: leases,
			Zone:         dns.Fqdn(strings.ToLower(cur.Raw.PrivateDomain)),
			ReverseZones: cur.ReverseZones,
		}, nil
	}, logger)
	if err := holder.Rebuild(); err != nil {
		return fmt.Errorf("initial snapshot: %w", err)
	}

	reg := registry.New(st, privateFQDN, func() error {
		if err := holder.Rebuild(); err != nil {
			// The write is already committed; the old snapshot keeps serving.
			logger.Error("snapshot rebuild failed, still serving the previous snapshot", "error", err)
			return err
		}
		return nil
	})

	// Filtering is on by default. Built-ins seed once; an operator's later
	// edits to them survive every upgrade.
	if err := policy.SeedBuiltins(st); err != nil {
		return err
	}
	policyHolder := policy.NewHolder(func() (store.BlacklistSettings, []store.BlacklistList, []store.BlacklistRule, error) {
		set, err := st.BlacklistSettings()
		if err != nil {
			return set, nil, nil, err
		}
		lists, err := st.BlacklistLists()
		if err != nil {
			return set, nil, nil, err
		}
		rules, err := st.BlacklistRules()
		return set, lists, rules, err
	})
	if err := policyHolder.Rebuild(); err != nil {
		return fmt.Errorf("initial blacklist policy: %w", err)
	}
	refresher := policy.NewRefresher(st, policy.NewFetcher(30*time.Second), policyHolder, logger)
	policySvc := policy.NewService(st, policyHolder, refresher, logger)

	if boot.DHCPLeaseFile != "" {
		poller = discovery.NewPoller(
			&dhcp.DnsmasqSource{Path: boot.DHCPLeaseFile},
			time.Duration(boot.DiscoveryInterval)*time.Second,
			func() {
				if err := holder.Rebuild(); err != nil {
					logger.Error("rebuild after lease change failed", "error", err)
				}
			}, logger)
	}

	if err := bootstrapToken(reg, cfg.DataDir, logger); err != nil {
		return err
	}

	acl := dnsserver.NewACL(snap.AllowQuery)
	// Logged from the snapshot, not the raw list: that is what the ACL enforces,
	// masked and with the CGNAT range already added.
	logger.Info("query acl", "ranges", snap.AllowQuery, "allow_tailscale", boot.AllowTailscale)
	warnUnreachableViews(st, boot.AllowTailscale, logger)

	cache := dnsserver.NewCache(boot.CacheEntries, boot.CacheMinTTL, boot.CacheMaxTTL, boot.NegativeMaxTTL)
	for _, u := range snap.Upstreams {
		if !u.Secure() {
			logger.Warn("upstream is unencrypted; answers from it cannot be authenticated",
				"upstream", u.String(),
				"fix", "use a tls:// or https:// upstream under Settings")
		}
	}
	fwd := dnsserver.NewForwarder(snap.Upstreams, 2*time.Second, cache)

	authoritative := dnsserver.NewAuthoritative(privateFQDN, uint32(boot.TTL), snap.ReverseZones)
	dnsSrv := dnsserver.New(dnsserver.Options{
		Holder: holder, ACL: acl,
		Auth:        authoritative,
		Forwarder:   fwd,
		Policy:      policySvc,
		LogQueries:  boot.LogQueries,
		LogClientIP: boot.LogClientIP,
		Logger:      logger,
	})
	// The cache reports its hits through the same counters as the query
	// pipeline, so the dashboard's hit rate and query totals cannot disagree.
	cache.SetMetrics(dnsSrv.Metrics())

	checker := health.NewChecker(reg,
		time.Duration(boot.HealthInterval)*time.Second,
		time.Duration(boot.HealthTimeout)*time.Second,
		boot.HealthWorkers, logger)

	live := &liveComponents{
		acl: acl, forwarder: fwd, cache: cache, dnsSrv: dnsSrv,
		authoritative: authoritative, checker: checker, poller: poller,
		zoneHolder: holder, registry: reg, logger: logger, prevUpstreams: boot.Upstreams,
	}
	settingsSvc := settings.NewService(st, settingsHolder, live.Apply)

	errs := make(chan error, 3)
	roleHolder := NewRoleHolder(RoleFrom(cfg.Replication))
	replSrv, repPuller, err := startReplication(ctx, cfg, st,
		&replicaApplier{st: st, settings: settingsHolder, policy: policyHolder, live: live},
		errs, logger)
	if err != nil {
		return err
	}
	if replSrv != nil {
		defer replSrv.Close()
	}

	leaseFn := func() []dhcp.Lease {
		if poller == nil {
			return nil
		}
		return poller.Leases()
	}

	// One mux serves both transports: the API owns /api/v1/... and the web
	// server owns everything else.
	api := adminapi.NewAPI(reg, acl, cache).
		WithProviders(leaseFn, checker.Statuses).
		WithPolicy(policySvc).
		WithSettings(settingsSvc).
		WithMetrics(dnsSrv.Metrics()).
		WithReplication(func() adminapi.ReplicaStatus {
			var p puller
			if repPuller != nil {
				p = repPuller
			}
			return replicaStatus(roleHolder.Current(), cfg.Replication.Primary, p).toAdminAPI()
		})
	mux := http.NewServeMux()
	api.Routes(mux)

	setupToken, err := ensureSetupToken(st, cfg.DataDir, logger)
	if err != nil {
		return err
	}
	web.New(web.Options{
		Store: st, Registry: reg, API: api, Config: cfg,
		Sessions:   auth.NewSessions(time.Hour, 12*time.Hour),
		Backoff:    auth.NewBackoff(),
		ACL:        acl,
		Cache:      cache,
		Metrics:    dnsSrv.Metrics(),
		Policy:     policySvc,
		Settings:   settingsSvc,
		Upstreams:  fwd.Status,
		SetupToken: setupToken,
		Logger:     logger,
		Health:     checker.Statuses,
		// Compared against the boot values on every page load: there is no
		// dirty flag to drift, and the banner clears itself on restart.
		RestartPending: func() []web.RestartItem {
			cur, err := settingsSvc.Get()
			if err != nil {
				return nil
			}
			var out []web.RestartItem
			for _, it := range restartPending(boot, cur) {
				out = append(out, web.RestartItem(it))
			}
			return out
		},
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
	go refresher.Run(ctx)
	set, err := policySvc.Settings()
	if err != nil {
		return err
	}
	logger.Info("kydns started",
		"dns", cfg.DNS.Listen, "admin", cfg.Admin.Listen, "zone", privateFQDN,
		"filtering", onOffLabel(set.Enabled))

	select {
	case err := <-errs:
		return err
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return errors.Join(dnsSrv.Shutdown(shutdown), adminSrv.Shutdown(shutdown))
}

// ensureSettings returns the settings the process will boot with. On a fresh
// database the config file seeds them; after that the database owns them and
// the file's moved keys are ignored.
func ensureSettings(st *store.Store, cfg *config.Config, logger *slog.Logger) (store.Settings, error) {
	cur, ok, err := st.Settings()
	if err != nil {
		return store.Settings{}, err
	}
	if ok {
		// Validate what we load: a database edited by hand, or written by an
		// older version, must not start a half-configured server.
		if err := settings.ValidateStored(cur); err != nil {
			return store.Settings{}, fmt.Errorf("stored settings: %w", err)
		}
		warnPublicACL(cur, logger)
		return cur, nil
	}
	seed := cfg.SeedSettings()
	if err := settings.ValidateStored(seed); err != nil {
		return store.Settings{}, fmt.Errorf("seed from config file: %w", err)
	}
	// Same masking the write path applies: a seeded "192.168.1.99/0" enforces
	// 0.0.0.0/0, and every surface must read back what the ACL actually does.
	seed = settings.Canonicalize(seed)
	if err := st.PutSettings(seed); err != nil {
		return store.Settings{}, err
	}
	logger.Info("seeded settings from the config file",
		"note", "later edits to those keys are ignored; use the web UI")
	warnPublicACL(seed, logger)
	return seed, nil
}

// warnPublicACL is the standing signal for an ACL that reaches past the LAN.
// Startup honours what is already configured rather than refusing to run, so
// this warning is the only thing that keeps a grandfathered open resolver
// visible to the operator. It reports the canonical, masked prefix: an entry of
// 192.168.1.99/0 matches everything while reading as a LAN address.
func warnPublicACL(v store.Settings, logger *slog.Logger) {
	for _, p := range settings.PublicPrefixes(v.AllowQuery) {
		logger.Warn("query ACL reaches beyond your LAN; KyDNS is an open resolver for this range",
			"prefix", p,
			"fix", "remove "+p+" from allow_query under Settings, Server settings")
	}
}

// flushOnUpstreamChange empties the cache when the upstream list changed:
// answers minted by a resolver the operator has just walked away from must not
// keep being served for up to cache_max_ttl. An unrelated save leaves the cache
// alone, because emptying it makes every client re-resolve.
// zoneChanged compares a running zone against a stored private domain. Case
// and the trailing dot are presentation, not a different zone.
func zoneChanged(running, stored string) bool {
	return store.ZoneSuffix(running) != store.ZoneSuffix(stored)
}

func flushOnUpstreamChange(c *dnsserver.Cache, prev, next []string, logger *slog.Logger) bool {
	if slices.Equal(prev, next) {
		return false
	}
	c.Flush()
	logger.Info("upstreams changed, cache flushed", "upstreams", next)
	return true
}

// RestartItem is one setting whose stored value differs from the one the
// process is running.
type RestartItem struct {
	Key     string
	Running string
	Stored  string
}

// restartPending compares the boot value of the one setting that cannot be
// applied live. There is no dirty flag to drift out of sync: the comparison
// becomes equal on the next restart and the banner clears itself.
//
// private_domain used to be here. It is applied live now: the zone is an
// atomic on the authoritative answerer and the registry, and Apply moves both.
func restartPending(boot, cur store.Settings) []RestartItem {
	var out []RestartItem
	add := func(key, running, stored string) {
		if running != stored {
			out = append(out, RestartItem{Key: key, Running: running, Stored: stored})
		}
	}
	add("dhcp_lease_file", orOff(boot.DHCPLeaseFile), orOff(cur.DHCPLeaseFile))
	return out
}

func orOff(s string) string {
	if s == "" {
		return "off"
	}
	return s
}

func onOffLabel(b bool) string {
	if b {
		return "on"
	}
	return "off"
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
func warnUnreachableViews(st *store.Store, allowTailscale bool, logger *slog.Logger) {
	if allowTailscale {
		return
	}
	cgnat := netip.MustParsePrefix(settings.TailscaleCGNAT)
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
				"fix", "turn on allow_tailscale under Settings")
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
