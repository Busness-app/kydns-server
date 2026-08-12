package adminapi

import (
	"net/http"
	"strings"
	"testing"
)

func TestExportCarriesPolicyButNeverListBodies(t *testing.T) {
	h, tok, _ := newBlacklistAPI(t)
	if rec := do(t, h, "POST", "/api/v1/blacklists/lists", tok,
		`{"name":"custom","url":"https://lists.example/hosts","format":"hosts","enabled":true,"interval_seconds":3600}`); rec.Code != http.StatusCreated {
		t.Fatal(rec.Body)
	}
	if rec := do(t, h, "POST", "/api/v1/blacklists/rules/deny", tok, `{"domain":"ads.example"}`); rec.Code != http.StatusCreated {
		t.Fatal(rec.Body)
	}

	rec := do(t, h, "GET", "/api/v1/export?format=json", tok, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("export = %d: %s", rec.Code, rec.Body)
	}
	body := rec.Body.String()
	for _, want := range []string{"blacklist", "custom", "https://lists.example/hosts", "ads.example"} {
		if !strings.Contains(body, want) {
			t.Errorf("export is missing %q", want)
		}
	}
	// The downloaded body, the cache validators and the failure text are
	// runtime state, not backup content.
	for _, leak := range []string{"snapshot", "etag", "last_error", "last_ok_at"} {
		if strings.Contains(body, leak) {
			t.Errorf("export leaks %q", leak)
		}
	}
}

func TestImportReplaceRestoresThePolicy(t *testing.T) {
	h, tok, svc := newBlacklistAPI(t)
	doc := `{"views":[],"services":[],"records":[],"blacklist":{
	  "enabled":false,"block_ttl":30,
	  "lists":[{"name":"restored","url":"https://lists.example/x","format":"domains","enabled":true,"interval_seconds":3600}],
	  "rules":[{"kind":"deny","domain":"bad.example"},{"kind":"allow","domain":"good.example"}]}}`
	if rec := do(t, h, "POST", "/api/v1/import?mode=replace", tok, doc); rec.Code != http.StatusOK {
		t.Fatalf("import = %d: %s", rec.Code, rec.Body)
	}
	set, err := svc.Settings()
	if err != nil {
		t.Fatal(err)
	}
	if set.Enabled || set.BlockTTL != 30 {
		t.Errorf("settings = %+v, want {false 30}", set)
	}
	lists, err := svc.Lists()
	if err != nil {
		t.Fatal(err)
	}
	// A replace-import also reseeds the shipped built-in, so the imported
	// definition sits alongside it rather than being the only list.
	var foundRestored bool
	for _, l := range lists {
		if l.Name == "restored" {
			foundRestored = true
		}
	}
	if !foundRestored {
		t.Errorf("lists = %+v, want the imported definition present", lists)
	}
	rules, err := svc.Rules()
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 2 {
		t.Errorf("rules = %+v, want both imported rules", rules)
	}
}

// A bad document must leave the previous policy untouched, not half-applied.
func TestImportValidatesBeforeReplacing(t *testing.T) {
	h, tok, svc := newBlacklistAPI(t)
	if rec := do(t, h, "POST", "/api/v1/blacklists/rules/deny", tok, `{"domain":"keep.example"}`); rec.Code != http.StatusCreated {
		t.Fatal(rec.Body)
	}
	bad := `{"views":[],"services":[],"records":[],"blacklist":{
	  "enabled":true,"block_ttl":60,
	  "lists":[{"name":"ok","url":"https://lists.example/x","format":"domains","enabled":true,"interval_seconds":3600},
	           {"name":"bad","url":"http://lists.example/y","format":"domains","enabled":true,"interval_seconds":3600}],
	  "rules":[]}}`
	if rec := do(t, h, "POST", "/api/v1/import?mode=replace", tok, bad); rec.Code != http.StatusBadRequest {
		t.Fatalf("import of a plain-http list = %d, want 400", rec.Code)
	}
	rules, err := svc.Rules()
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 || rules[0].Domain != "keep.example" {
		t.Errorf("rules = %+v, want the prior policy untouched", rules)
	}
	lists, err := svc.Lists()
	if err != nil {
		t.Fatal(err)
	}
	if len(lists) != 0 {
		t.Errorf("lists = %+v, want nothing written from the rejected document", lists)
	}
}

// Merge adds without wiping, and an omitted blacklist block changes nothing.
func TestImportMergeAddsAndOmissionChangesNothing(t *testing.T) {
	h, tok, svc := newBlacklistAPI(t)
	if rec := do(t, h, "POST", "/api/v1/blacklists/rules/deny", tok, `{"domain":"keep.example"}`); rec.Code != http.StatusCreated {
		t.Fatal(rec.Body)
	}
	merge := `{"views":[],"services":[],"records":[],"blacklist":{
	  "enabled":true,"block_ttl":60,
	  "lists":[{"name":"added","url":"https://lists.example/x","format":"domains","enabled":true,"interval_seconds":3600}],
	  "rules":[{"kind":"deny","domain":"added.example"}]}}`
	if rec := do(t, h, "POST", "/api/v1/import?mode=merge", tok, merge); rec.Code != http.StatusOK {
		t.Fatalf("merge = %d: %s", rec.Code, rec.Body)
	}
	rules, err := svc.Rules()
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 2 {
		t.Errorf("rules = %+v, want the existing rule kept and the new one added", rules)
	}

	if rec := do(t, h, "POST", "/api/v1/import?mode=merge", tok, `{"views":[],"services":[],"records":[]}`); rec.Code != http.StatusOK {
		t.Fatalf("merge with no blacklist block = %d", rec.Code)
	}
	after, err := svc.Rules()
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != 2 {
		t.Errorf("rules = %+v, want a document with no blacklist block to change nothing", after)
	}
}
