// Package app wires the process together. It is the only place that knows
// about every other package.
package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
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

	"github.com/Busness-app/ky-primitives/recoveryclient"
	"github.com/miekg/dns"

	"github.com/Busness-app/kydns-server/internal/adminapi"
	"github.com/Busness-app/kydns-server/internal/auth"
	"github.com/Busness-app/kydns-server/internal/backup"
	"github.com/Busness-app/kydns-server/internal/config"
	"github.com/Busness-app/kydns-server/internal/discovery"
	"github.com/Busness-app/kydns-server/internal/discovery/dhcp"
	"github.com/Busness-app/kydns-server/internal/dnsserver"
	"github.com/Busness-app/kydns-server/internal/health"
	"github.com/Busness-app/kydns-server/internal/policy"
	"github.com/Busness-app/kydns-server/internal/registry"
	"github.com/Busness-app/kydns-server/internal/settings"
	"github.com/Busness-app/kydns-server/internal/store"
	"github.com/Busness-app/kydns-server/internal/web"
	"github.com/Busness-app/kydns-server/internal/zone"
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
	logEnvOverrides(cfg, logger)
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
		// Still guarded: the poller's onChange rebuilds this holder, so the
		// holder is built first and the initial Rebuild below runs while the
		// variable is genuinely nil.
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

	// Declared before the callback so it captures the variable; it is
	// assigned below, once the role it reads has been decided.
	var dhcpRun *dhcpRunner

	reg := registry.New(st, privateFQDN, func() error {
		// A service's address or MAC changing changes what its reservation
		// resolves to, so this is the same event.
		if dhcpRun != nil {
			dhcpRun.RefreshReservations()
		}
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

	// The poller always exists and always runs: its source is swapped at
	// runtime, which is what lets both dhcp_lease_file and the built-in server
	// be turned on and off without a restart. A nil source is discovery off.
	poller = discovery.NewPoller(
		nil,
		time.Duration(boot.DiscoveryInterval)*time.Second,
		func() {
			if err := holder.Rebuild(); err != nil {
				logger.Error("rebuild after lease change failed", "error", err)
			}
		}, logger)
	if boot.DHCPLeaseFile != "" {
		poller.SetSource(&dhcp.DnsmasqSource{Path: boot.DHCPLeaseFile})
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

	// The role is decided here, ahead of the live components, because the DHCP
	// runner reads it and the live components hold the runner.
	promotedAt, err := st.Promotion()
	if err != nil {
		return err
	}
	role := RoleAtBoot(cfg.Replication, promotedAt != 0)
	if promotedAt != 0 && cfg.Replication.Primary != "" {
		logger.Info("this node was promoted to primary; replication.primary in the config file is ignored",
			"promoted_at", promotedAt, "primary", cfg.Replication.Primary,
			"fix", "remove replication.primary, or run kydns replica join to make this node a replica again")
	}
	roleHolder := NewRoleHolder(role)

	// Read per Reconcile rather than captured, so a promotion starts DHCP
	// without a restart.
	dhcpRun = &dhcpRunner{
		poller:   poller,
		store:    st,
		logger:   logger,
		services: st.Services,
		onChange: func() {
			if err := poller.Poll(ctx); err != nil {
				logger.Warn("lease refresh after a dhcp change failed", "error", err)
			}
		},
		role: roleHolder.Current,
	}
	dhcpRun.Reconcile(snap.Raw)

	live := &liveComponents{
		acl: acl, forwarder: fwd, cache: cache, dnsSrv: dnsSrv,
		authoritative: authoritative, checker: checker, poller: poller,
		zoneHolder: holder, registry: reg, logger: logger, prevUpstreams: boot.Upstreams,
		dhcp: dhcpRun,
	}
	// The role is read per write, not captured: a replica may configure its own
	// node-local DHCP settings and nothing else, and promotion must widen that
	// without a restart.
	settingsSvc := settings.NewService(st, settingsHolder, live.Apply,
		func() bool { return roleHolder.Current() == RoleReplica })

	errs := make(chan error, 3)
	repl, err := startReplication(ctx, cfg, role, st,
		&replicaApplier{st: st, settings: settingsHolder, policy: policyHolder, live: live},
		checker.Statuses, logger)
	if err != nil {
		return err
	}
	if repl.srv != nil {
		defer repl.srv.Close()
	}
	nodeID := ""
	if repl.id != nil {
		nodeID = repl.id.NodeID
	}

	// A replica shows the health its primary reports, not what it probes
	// itself: it sits on the other side of the network from the services, and
	// its own verdict would keep reading "up" while the primary is unreachable.
	// The role decides, not the puller, so an unpaired replica reports unknown
	// rather than falling back to its own probes. A promoted node owns the
	// probes again, and reads the local checker.
	healthFn := checker.Statuses
	if role == RoleReplica {
		healthFn = func() []health.Status {
			if roleHolder.Current() != RoleReplica {
				return checker.Statuses()
			}
			return replicaHealth(st, repl.puller, logger)
		}
	}

	// Always wired. Whether discovery is on is a separate question, answered
	// per request by the poller's current source rather than by this being nil.
	leaseFn := poller.Leases

	// One producer for both transports, read per request so promotion moves
	// them together.
	replStatus := func() ReplicaStatus {
		var p puller
		// Only while this node is still a replica: a promoted node's stopped
		// loop would otherwise keep reporting a primary and a stale sync time.
		if repl.puller != nil && roleHolder.Current() == RoleReplica {
			p = repl.puller
		}
		return replicaStatus(roleHolder.Current(), cfg.Replication.Primary, nodeID, p)
	}

	backupSvc, err := backup.New(cfg, st, web.Version)
	if err != nil {
		return err
	}
	if cfg.BackupAllowPrivateRecovery {
		logger.Warn("KYDNS_BACKUP_ALLOW_PRIVATE_RECOVERY is set: private and CGNAT KyRecovery addresses admitted; HTTPS still required")
	}
	// One mux serves both transports: the API owns /api/v1/... and the web
	// server owns everything else.
	api := adminapi.NewAPI(reg, acl, cache).
		WithProviders(leaseFn, healthFn, poller.Enabled).
		WithPolicy(policySvc).
		WithSettings(settingsSvc).
		WithMetrics(dnsSrv.Metrics()).
		WithReplication(func() adminapi.ReplicaStatus { return replStatus().toAdminAPI() }).
		WithDHCP(dhcpRun).
		WithBackupService(backupSvc).
		WithReplicaAdmin(&replicaAdmin{st: st, srv: repl.srv}).
		// Wired on every node: promotion answers "already a primary" rather than
		// an error, and a replica must never find this endpoint missing.
		WithReplicaPromoter(&replicaPromoter{st: st, role: roleHolder, stopPull: repl.stopPull,
			// Promotion starts the listener. Waiting for the next settings save
			// would leave the LAN without DHCP at the one moment the primary it
			// was following has gone.
			onPromote: func() { dhcpRun.Reconcile(settingsHolder.Current().Raw) }})
	// Pairing needs this node's key, so it is offered only where there is one.
	if repl.id != nil {
		api = api.WithReplicaJoiner(&replicaJoiner{st: st, id: repl.id})
	}
	mux := http.NewServeMux()
	api.Routes(mux)

	setupToken, err := ensureSetupToken(st, cfg.DataDir, logger)
	if err != nil {
		return err
	}
	webSrv := web.New(web.Options{
		Store: st, Registry: reg, API: api, Config: cfg,
		Sessions:    auth.NewSessions(time.Hour, 12*time.Hour),
		Backoff:     auth.NewBackoff(),
		ACL:         acl,
		Cache:       cache,
		Metrics:     dnsSrv.Metrics(),
		Policy:      policySvc,
		Settings:    settingsSvc,
		Upstreams:   fwd.Status,
		SetupToken:  setupToken,
		Logger:      logger,
		Health:      healthFn,
		Replication: func() web.ReplicaStatus { return replStatus().toWeb() },
		Backup:      backupSvc,
		// Left nil: no setting the database owns needs a restart any more.
		// private_domain moved to a live swap, and dhcp_lease_file went with
		// the built-in DHCP server — the poller always exists now and Apply
		// swaps its source, so a banner naming it would send an operator to
		// restart a server that has already picked the file up. web renders no
		// banner for a nil provider.
		Leases: leaseFn,
		// Read per request, not fixed at construction: the built-in server and
		// a lease file both come and go at runtime, and the screen has to say
		// "discovery is off" rather than render an empty table.
		DiscoveryOn: poller.Enabled,
	})
	webSrv.Routes(mux)

	adminSrv := &http.Server{
		Addr: cfg.Admin.Listen,
		// Both gates sit outside the mux, so a replica refuses every write:
		// one added later, or one on a path with no route at all. Each answers
		// in its own transport's language.
		Handler:           api.WriteGate(webSrv.WriteGate(mux)),
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() { errs <- dnsSrv.ListenAndServe(cfg.DNS.Listen) }()
	go func() {
		if err := adminSrv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			errs <- err
		}
	}()
	go poller.Run(ctx)
	go checker.Run(ctx)
	go refresher.Run(ctx)
	go backupLoop(ctx, backupSvc, logger)
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

// backupLoop polls the schedule every minute so an admin's change needs no restart. The
// next run counts from the last attempt, successful or not, so a dead destination is
// retried once per interval. An upload already started outlives SIGTERM.
func backupLoop(ctx context.Context, svc *backup.Service, logger *slog.Logger) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		st, err := svc.Status()
		if err != nil {
			logger.Error("backup schedule unreadable", "error", recoveryclient.AuditSafe(err.Error()))
			continue
		}
		if st.NextRun == nil || time.Now().Before(*st.NextRun) {
			continue
		}
		upload, cancel := context.WithTimeout(context.WithoutCancel(ctx), 16*time.Minute)
		res, err := svc.Run(upload)
		cancel()
		// Not configured is not a failure to report every interval.
		if errors.Is(err, recoveryclient.ErrNotPaired) || errors.Is(err, recoveryclient.ErrNoDestination) {
			continue
		}
		action, outcome, details := recoveryclient.Outcome(res, err)
		b, _ := json.Marshal(details)
		_ = svc.Store.RecordAudit(store.AuditEvent{Actor: "scheduler", Action: action,
			Resource: res.Manifest.CapsuleID, Details: string(b), Outcome: outcome})
		if err != nil {
			logger.Error("scheduled backup failed", "error", recoveryclient.AuditSafe(err.Error()))
		}
	}
}

// logEnvOverrides records which file-owned settings the environment replaced.
// Without it, a variable set once and forgotten contradicts the operator's
// file at every start with nothing to say so.
func logEnvOverrides(cfg *config.Config, logger *slog.Logger) {
	keys := cfg.EnvOverrides()
	if len(keys) == 0 {
		return
	}
	logger.Info("configuration overridden from the environment",
		"variables", strings.Join(keys, " "),
		"note", "these replace the matching keys in the config file")
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
