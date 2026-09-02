package web

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Busness-app/kydns-server/internal/store"
)

var errNoSuchList = errors.New("no such list")

// blacklistRow is one list as the table shows it. Status is the plain-language
// state an operator acts on, not a raw error.
type blacklistRow struct {
	ID          int64
	Name        string
	Description string
	URL         string
	Format      string
	Enabled     bool
	Builtin     bool
	Interval    string
	Entries     int
	Skipped     int
	LastOK      string
	Stale       bool
	NeverLoaded bool
	LastError   string
}

func agoOrNever(unix int64) string {
	if unix == 0 {
		return "never"
	}
	return time.Unix(unix, 0).UTC().Format("2006-01-02 15:04 UTC")
}

func (s *Server) blacklistsData(errMsg string, result map[string]any) map[string]any {
	data := map[string]any{
		"Title": "Blacklists", "Nav": "blacklists", "Result": result,
	}
	if s.o.Policy == nil {
		data["Unavailable"] = true
		data["Error"] = errMsg
		return data
	}

	set, err := s.o.Policy.Settings()
	if err != nil && errMsg == "" {
		errMsg = err.Error()
	}
	data["Enabled"] = set.Enabled
	data["BlockTTL"] = set.BlockTTL

	lists, err := s.o.Policy.Lists()
	if err != nil && errMsg == "" {
		errMsg = err.Error()
	}
	rows := make([]blacklistRow, 0, len(lists))
	staleAny := false
	for _, l := range lists {
		row := blacklistRow{
			ID: l.ID, Name: l.Name, Description: l.Description, URL: l.URL,
			Format: l.Format, Enabled: l.Enabled, Builtin: l.Builtin,
			Interval: strconv.FormatInt(l.IntervalSeconds/60, 10) + " min",
			Entries:  l.EntryCount, Skipped: l.SkippedCount,
			LastOK: agoOrNever(l.LastOKAt),
			// A failed refresh does not stop the list working: the last good
			// snapshot is still in force, so this reads "stale", not "broken".
			Stale:       l.LastError != "" && l.LastOKAt != 0,
			NeverLoaded: l.LastOKAt == 0,
			LastError:   l.LastError,
		}
		if row.Stale || (row.NeverLoaded && l.Enabled) {
			staleAny = true
		}
		rows = append(rows, row)
	}
	data["Lists"] = rows
	data["StaleAny"] = staleAny

	rules, err := s.o.Policy.Rules()
	if err != nil && errMsg == "" {
		errMsg = err.Error()
	}
	var allow, deny []store.BlacklistRule
	for _, r := range rules {
		if r.Kind == "allow" {
			allow = append(allow, r)
			continue
		}
		deny = append(deny, r)
	}
	data["Allow"], data["Deny"] = allow, deny

	total, byList := s.o.Policy.Counters()
	data["BlockedTotal"] = total
	data["BlockedByList"] = byList
	data["Error"] = errMsg
	return data
}

func (s *Server) getBlacklists(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "blacklists.html", s.blacklistsData("", nil))
}

// blacklistsError re-renders the page with a field-level message rather than
// replacing it with a bare error page.
func (s *Server) blacklistsError(w http.ResponseWriter, r *http.Request, err error) {
	w.WriteHeader(http.StatusBadRequest)
	s.render(w, r, "blacklists.html", s.blacklistsData(err.Error(), nil))
}

func (s *Server) requirePolicy(w http.ResponseWriter) bool {
	if s.o.Policy == nil {
		http.Error(w, "blacklist filtering is not enabled", http.StatusNotFound)
		return false
	}
	return true
}

// postBlacklistToggle flips the global switch. It deletes nothing: turning
// filtering back on restores every list and rule immediately.
func (s *Server) postBlacklistToggle(w http.ResponseWriter, r *http.Request) {
	if !s.requirePolicy(w) {
		return
	}
	set, err := s.o.Policy.Settings()
	if err != nil {
		s.blacklistsError(w, r, err)
		return
	}
	if err := s.o.Policy.SetSettings(!set.Enabled, set.BlockTTL); err != nil {
		s.blacklistsError(w, r, err)
		return
	}
	http.Redirect(w, r, "/blacklists", http.StatusSeeOther)
}

func (s *Server) postBlacklistListNew(w http.ResponseWriter, r *http.Request) {
	if !s.requirePolicy(w) {
		return
	}
	interval, _ := strconv.ParseInt(strings.TrimSpace(r.PostFormValue("interval")), 10, 64)
	l := store.BlacklistList{
		Name:            r.PostFormValue("name"),
		URL:             r.PostFormValue("url"),
		Format:          r.PostFormValue("format"),
		Enabled:         true,
		IntervalSeconds: interval,
	}
	if _, err := s.o.Policy.PutList(l); err != nil {
		s.blacklistsError(w, r, err)
		return
	}
	http.Redirect(w, r, "/blacklists", http.StatusSeeOther)
}

// postBlacklistListToggle enables or disables one list, leaving its downloaded
// body alone.
func (s *Server) postBlacklistListToggle(w http.ResponseWriter, r *http.Request) {
	if !s.requirePolicy(w) {
		return
	}
	id, err := strconv.ParseInt(r.PostFormValue("id"), 10, 64)
	if err != nil {
		s.blacklistsError(w, r, err)
		return
	}
	lists, err := s.o.Policy.Lists()
	if err != nil {
		s.blacklistsError(w, r, err)
		return
	}
	for _, l := range lists {
		if l.ID != id {
			continue
		}
		l.Enabled = !l.Enabled
		if _, err := s.o.Policy.PutList(l); err != nil {
			s.blacklistsError(w, r, err)
			return
		}
		http.Redirect(w, r, "/blacklists", http.StatusSeeOther)
		return
	}
	s.blacklistsError(w, r, errNoSuchList)
}

func (s *Server) postBlacklistListDelete(w http.ResponseWriter, r *http.Request) {
	if !s.requirePolicy(w) {
		return
	}
	id, err := strconv.ParseInt(r.PostFormValue("id"), 10, 64)
	if err == nil {
		err = s.o.Policy.DeleteList(id)
	}
	if err != nil {
		s.blacklistsError(w, r, err)
		return
	}
	http.Redirect(w, r, "/blacklists", http.StatusSeeOther)
}

// postBlacklistRefresh downloads one list, or every list when the id field is
// missing or empty. A present-but-unparseable id is an error, not "all": a
// typo must never trigger a full re-download of every list.
func (s *Server) postBlacklistRefresh(w http.ResponseWriter, r *http.Request) {
	if !s.requirePolicy(w) {
		return
	}
	var id int64
	if raw := strings.TrimSpace(r.PostFormValue("id")); raw != "" {
		v, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			s.blacklistsError(w, r, err)
			return
		}
		id = v
	}
	if err := s.o.Policy.Refresh(r.Context(), id); err != nil {
		s.blacklistsError(w, r, err)
		return
	}
	http.Redirect(w, r, "/blacklists", http.StatusSeeOther)
}

func (s *Server) postBlacklistRuleNew(w http.ResponseWriter, r *http.Request) {
	if !s.requirePolicy(w) {
		return
	}
	if _, err := s.o.Policy.AddRule(r.PostFormValue("kind"), r.PostFormValue("domain")); err != nil {
		s.blacklistsError(w, r, err)
		return
	}
	http.Redirect(w, r, "/blacklists", http.StatusSeeOther)
}

func (s *Server) postBlacklistRuleDelete(w http.ResponseWriter, r *http.Request) {
	if !s.requirePolicy(w) {
		return
	}
	id, err := strconv.ParseInt(r.PostFormValue("id"), 10, 64)
	if err == nil {
		err = s.o.Policy.DeleteRule(id)
	}
	if err != nil {
		s.blacklistsError(w, r, err)
		return
	}
	http.Redirect(w, r, "/blacklists", http.StatusSeeOther)
}

// postBlacklistTest renders the page directly rather than redirecting, because
// the result exists only in this response.
func (s *Server) postBlacklistTest(w http.ResponseWriter, r *http.Request) {
	if !s.requirePolicy(w) {
		return
	}
	name := strings.TrimSpace(r.PostFormValue("name"))
	d, err := s.o.Policy.Test(name)
	if err != nil {
		s.blacklistsError(w, r, err)
		return
	}
	s.render(w, r, "blacklists.html", s.blacklistsData("", map[string]any{
		"Name": name, "Blocked": d.Blocked, "Policy": d.Policy,
	}))
}
