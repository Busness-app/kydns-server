package policy

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/yoshiofthewire/kydns-server/internal/store"
)

// RefreshCadence is the foreground scheduler tick. Each list still obeys its
// own interval, so a 90-second tick does not mean a 90-second download.
const RefreshCadence = 90 * time.Second

// Refresher downloads and installs list bodies. Now is swappable so a test can
// step past an interval without sleeping.
type Refresher struct {
	st     *store.Store
	f      *Fetcher
	h      *Holder
	logger *slog.Logger
	Now    func() time.Time
}

func NewRefresher(st *store.Store, f *Fetcher, h *Holder, logger *slog.Logger) *Refresher {
	if logger == nil {
		logger = slog.Default()
	}
	return &Refresher{st: st, f: f, h: h, logger: logger, Now: time.Now}
}

// Run refreshes due lists on the foreground cadence, catching up immediately
// on start rather than waiting out a first tick.
func (r *Refresher) Run(ctx context.Context) {
	t := time.NewTicker(RefreshCadence)
	defer t.Stop()
	for {
		r.RefreshDue(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// RefreshDue refreshes every enabled list whose interval has elapsed. A list
// that fails is logged and skipped: one bad source never stops the others.
func (r *Refresher) RefreshDue(ctx context.Context) {
	lists, err := r.st.BlacklistListMetas()
	if err != nil {
		r.logger.Warn("blacklist: list sources", "error", err)
		return
	}
	now := r.Now().Unix()
	changed := false
	for _, l := range lists {
		if !l.Enabled || now-l.LastAttemptAt < l.IntervalSeconds {
			continue
		}
		if _, c := r.refresh(ctx, l); c {
			changed = true
		}
	}
	if changed {
		r.rebuild()
	}
}

// RefreshAll refreshes every enabled list now, ignoring intervals. This is the
// "refresh all" button.
func (r *Refresher) RefreshAll(ctx context.Context) error {
	lists, err := r.st.BlacklistListMetas()
	if err != nil {
		return err
	}
	var joined error
	for _, l := range lists {
		if !l.Enabled {
			continue
		}
		if ok, _ := r.refresh(ctx, l); !ok {
			joined = errors.Join(joined, errors.New("refresh failed: "+l.Name))
		}
	}
	r.rebuild()
	return joined
}

// RefreshList refreshes one list now, ignoring its interval.
func (r *Refresher) RefreshList(ctx context.Context, id int64) error {
	l, err := r.st.BlacklistListByID(id)
	if err != nil {
		return err
	}
	if ok, _ := r.refresh(ctx, l); !ok {
		after, lookupErr := r.st.BlacklistListByID(id)
		if lookupErr == nil && after.LastError != "" {
			return errors.New(after.LastError)
		}
		return errors.New("refresh failed")
	}
	r.rebuild()
	return nil
}

// refresh downloads, parses and installs one list. It reports whether the
// attempt succeeded and whether the stored snapshot changed — a 304 succeeds
// without changing anything. Every failure path leaves the previous snapshot
// exactly where it was.
func (r *Refresher) refresh(ctx context.Context, l store.BlacklistList) (ok, changed bool) {
	at := r.Now().Unix()
	res, err := r.f.Fetch(ctx, l.URL, l.ETag, l.LastModified)
	if err != nil {
		r.fail(l, err, at)
		return false, false
	}
	if res.NotModified {
		if err := r.st.TouchBlacklistAttempt(l.ID, at); err != nil {
			r.logger.Warn("blacklist: record refresh", "list", l.Name, "error", err)
		}
		r.logger.Info("blacklist list unchanged", "list", l.Name, "entries", l.EntryCount)
		return true, false
	}
	parsed, err := Parse(bytes.NewReader(res.Body), l.Format)
	if err != nil {
		r.fail(l, err, at)
		return false, false
	}
	// A body that yields nothing usable is a broken source, not an empty list.
	// Installing it would silently unblock everything the list covered.
	if len(parsed.Domains) == 0 {
		r.fail(l, errors.New("no usable domains in the downloaded body"), at)
		return false, false
	}
	if err := r.st.SetBlacklistSnapshot(l.ID, parsed.Domains, parsed.Skipped,
		res.ETag, res.LastModified, at); err != nil {
		r.fail(l, err, at)
		return false, false
	}
	// Counts only: never the URL's credentials, never the content.
	r.logger.Info("blacklist list refreshed",
		"list", l.Name, "entries", len(parsed.Domains), "skipped", parsed.Skipped)
	return true, true
}

func (r *Refresher) fail(l store.BlacklistList, cause error, at int64) {
	if err := r.st.SetBlacklistError(l.ID, cause.Error(), at); err != nil {
		r.logger.Warn("blacklist: record failure", "list", l.Name, "error", err)
	}
	r.logger.Warn("blacklist list refresh failed, still serving the previous snapshot",
		"list", l.Name, "entries", l.EntryCount, "error", cause)
}

func (r *Refresher) rebuild() {
	if err := r.h.Rebuild(); err != nil {
		r.logger.Error("blacklist: rebuild failed, still serving the previous policy", "error", err)
	}
}
