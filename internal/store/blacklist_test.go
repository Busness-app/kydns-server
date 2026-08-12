package store

import (
	"errors"
	"testing"
)

func TestBlacklistDefaultsAreOn(t *testing.T) {
	s := open(t)
	got, err := s.BlacklistSettings()
	if err != nil {
		t.Fatal(err)
	}
	if !got.Enabled || got.BlockTTL != 60 {
		t.Errorf("BlacklistSettings() = %+v, want filtering on with a 60s block TTL", got)
	}
}

func TestBlacklistSettingsRoundTrip(t *testing.T) {
	s := open(t)
	if err := s.SetBlacklistSettings(BlacklistSettings{Enabled: false, BlockTTL: 30}); err != nil {
		t.Fatal(err)
	}
	got, err := s.BlacklistSettings()
	if err != nil {
		t.Fatal(err)
	}
	if got.Enabled || got.BlockTTL != 30 {
		t.Errorf("BlacklistSettings() = %+v, want {false 30}", got)
	}
}

func TestBlacklistListRoundTripsAndKeepsItsSnapshot(t *testing.T) {
	s := open(t)
	id, err := s.PutBlacklistList(BlacklistList{
		Name: "steven-black", URL: "https://lists.example/hosts",
		Format: "hosts", Enabled: true, Builtin: true,
		Description: "unified hosts", IntervalSeconds: 86400,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetBlacklistSnapshot(id, []string{"ads.example", "tracker.test"}, 7, "W/\"abc\"", "Mon, 01 Jan 2026 00:00:00 GMT", 1000); err != nil {
		t.Fatal(err)
	}

	got, err := s.BlacklistListByID(id)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Snapshot) != 2 || got.Snapshot[0] != "ads.example" {
		t.Errorf("Snapshot = %v, want the two stored domains", got.Snapshot)
	}
	if got.EntryCount != 2 || got.SkippedCount != 7 || got.LastOKAt != 1000 || got.LastError != "" {
		t.Errorf("metadata = %+v, want 2 entries, 7 skipped, ok at 1000, no error", got)
	}
	if got.ETag != "W/\"abc\"" || got.LastModified == "" {
		t.Errorf("validators = %q / %q, want both stored", got.ETag, got.LastModified)
	}

	// An edit to the definition must not disturb the downloaded snapshot.
	got.Enabled = false
	got.Description = "renamed"
	if _, err := s.PutBlacklistList(got); err != nil {
		t.Fatal(err)
	}
	after, err := s.BlacklistListByID(id)
	if err != nil {
		t.Fatal(err)
	}
	if len(after.Snapshot) != 2 || after.EntryCount != 2 || after.LastOKAt != 1000 {
		t.Errorf("after a definition edit = %+v, want the snapshot untouched", after)
	}
	if after.Enabled || after.Description != "renamed" {
		t.Errorf("after a definition edit = %+v, want the edit applied", after)
	}
}

// A failed refresh records the error and the attempt, and keeps the last good
// snapshot serving.
func TestSetBlacklistErrorKeepsTheSnapshot(t *testing.T) {
	s := open(t)
	id, err := s.PutBlacklistList(BlacklistList{Name: "l", URL: "https://e/x", Format: "domains", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetBlacklistSnapshot(id, []string{"ads.example"}, 0, "", "", 100); err != nil {
		t.Fatal(err)
	}
	if err := s.SetBlacklistError(id, "dial tcp: i/o timeout", 200); err != nil {
		t.Fatal(err)
	}
	got, err := s.BlacklistListByID(id)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Snapshot) != 1 || got.LastOKAt != 100 {
		t.Errorf("= %+v, want the last good snapshot retained", got)
	}
	if got.LastError == "" || got.LastAttemptAt != 200 {
		t.Errorf("= %+v, want the failure recorded", got)
	}
}

func TestBlacklistListMetasOmitSnapshots(t *testing.T) {
	s := open(t)
	id, err := s.PutBlacklistList(BlacklistList{Name: "l", URL: "https://e/x", Format: "domains", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetBlacklistSnapshot(id, []string{"ads.example"}, 0, "", "", 100); err != nil {
		t.Fatal(err)
	}
	metas, err := s.BlacklistListMetas()
	if err != nil {
		t.Fatal(err)
	}
	if len(metas) != 1 || metas[0].Snapshot != nil || metas[0].EntryCount != 1 {
		t.Errorf("BlacklistListMetas() = %+v, want the count without the body", metas)
	}
}

func TestDuplicateListNameRejected(t *testing.T) {
	s := open(t)
	l := BlacklistList{Name: "dup", URL: "https://e/x", Format: "domains", Enabled: true}
	if _, err := s.PutBlacklistList(l); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PutBlacklistList(l); !errors.Is(err, ErrDuplicateName) {
		t.Errorf("second PutBlacklistList = %v, want ErrDuplicateName", err)
	}
}

// One domain may hold at most one rule, which is how a rule that is both
// allowed and denied is refused at the schema level rather than by a check
// that some future caller could skip.
func TestConflictingRuleRejected(t *testing.T) {
	s := open(t)
	if _, err := s.PutBlacklistRule(BlacklistRule{Kind: "deny", Domain: "ads.example"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PutBlacklistRule(BlacklistRule{Kind: "allow", Domain: "ads.example"}); !errors.Is(err, ErrDuplicateName) {
		t.Errorf("conflicting rule = %v, want ErrDuplicateName", err)
	}
	if _, err := s.PutBlacklistRule(BlacklistRule{Kind: "deny", Domain: "ads.example"}); !errors.Is(err, ErrDuplicateName) {
		t.Errorf("duplicate rule = %v, want ErrDuplicateName", err)
	}
}

func TestRuleDelete(t *testing.T) {
	s := open(t)
	id, err := s.PutBlacklistRule(BlacklistRule{Kind: "allow", Domain: "good.example"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteBlacklistRule(id); err != nil {
		t.Fatal(err)
	}
	rules, err := s.BlacklistRules()
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 0 {
		t.Errorf("BlacklistRules() = %v, want empty", rules)
	}
	if err := s.DeleteBlacklistRule(id); !errors.Is(err, ErrNotFound) {
		t.Errorf("second delete = %v, want ErrNotFound", err)
	}
}

// Replace preserves a surviving list's downloaded body, so importing a backup
// does not force every list to re-download.
func TestReplaceBlacklistPreservesSnapshotsByURL(t *testing.T) {
	s := open(t)
	id, err := s.PutBlacklistList(BlacklistList{Name: "keep", URL: "https://e/x", Format: "domains", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetBlacklistSnapshot(id, []string{"ads.example"}, 0, "etag", "", 100); err != nil {
		t.Fatal(err)
	}
	if err := s.ReplaceBlacklist(
		BlacklistSettings{Enabled: true, BlockTTL: 60},
		[]BlacklistList{{Name: "keep-renamed", URL: "https://e/x", Format: "domains", Enabled: true}},
		[]BlacklistRule{{Kind: "deny", Domain: "bad.example"}},
	); err != nil {
		t.Fatal(err)
	}
	lists, err := s.BlacklistLists()
	if err != nil {
		t.Fatal(err)
	}
	if len(lists) != 1 || lists[0].Name != "keep-renamed" {
		t.Fatalf("BlacklistLists() = %+v, want the imported definition", lists)
	}
	if len(lists[0].Snapshot) != 1 || lists[0].ETag != "etag" || lists[0].LastOKAt != 100 {
		t.Errorf("= %+v, want the prior snapshot preserved by URL", lists[0])
	}
	rules, err := s.BlacklistRules()
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 || rules[0].Domain != "bad.example" {
		t.Errorf("BlacklistRules() = %+v, want only the imported rule", rules)
	}
}
