package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestRecordCreateAndList(t *testing.T) {
	h, _, c, csrf := loggedIn(t)
	rec := postForm(t, h, "/records/new", url.Values{
		"name": {"printer.home.arpa."}, "type": {"A"}, "value": {"192.168.1.50"},
		"csrf_token": {csrf},
	}, c)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("create = %d: %s", rec.Code, rec.Body)
	}
	body := page(t, h, "/records", c)
	for _, want := range []string{"printer.home.arpa.", "192.168.1.50", "A"} {
		if !strings.Contains(body, want) {
			t.Errorf("records page missing %q", want)
		}
	}
}

func TestRecordTypeDropdownIsLimitedToV1Types(t *testing.T) {
	h, _, c, _ := loggedIn(t)
	body := page(t, h, "/records", c)
	for _, want := range []string{`value="A"`, `value="AAAA"`, `value="CNAME"`, `value="PTR"`} {
		if !strings.Contains(body, want) {
			t.Errorf("type dropdown missing %s", want)
		}
	}
	for _, unwanted := range []string{`value="TXT"`, `value="MX"`, `value="SRV"`} {
		if strings.Contains(body, unwanted) {
			t.Errorf("type dropdown offers unsupported %s", unwanted)
		}
	}
}

func TestRecordRejectsUnsupportedType(t *testing.T) {
	h, _, c, csrf := loggedIn(t)
	rec := postForm(t, h, "/records/new", url.Values{
		"name": {"x.home.arpa."}, "type": {"TXT"}, "value": {"hello"}, "csrf_token": {csrf},
	}, c)
	if rec.Code == http.StatusSeeOther {
		t.Error("TXT record accepted, want rejection")
	}
}

func TestRecordRejectsOutOfZoneName(t *testing.T) {
	h, _, c, csrf := loggedIn(t)
	rec := postForm(t, h, "/records/new", url.Values{
		"name": {"evil.example.com."}, "type": {"A"}, "value": {"192.168.1.1"}, "csrf_token": {csrf},
	}, c)
	if rec.Code == http.StatusSeeOther {
		t.Error("out-of-zone record accepted, want rejection")
	}
}

// A PTR must live under in-addr.arpa, not merely under .arpa — the private
// domain home.arpa is itself under .arpa.
func TestRecordRejectsPTROutsideReverseNamespace(t *testing.T) {
	h, _, c, csrf := loggedIn(t)
	rec := postForm(t, h, "/records/new", url.Values{
		"name": {"x.home.arpa."}, "type": {"PTR"}, "value": {"y.home.arpa."}, "csrf_token": {csrf},
	}, c)
	if rec.Code == http.StatusSeeOther {
		t.Error("PTR in the forward zone accepted, want rejection")
	}
}

func TestRecordWithViewTag(t *testing.T) {
	h, srv, c, csrf := loggedIn(t)
	addView(t, srv, "tailnet", "100.64.0.0/10")
	rec := postForm(t, h, "/records/new", url.Values{
		"name": {"printer.home.arpa."}, "type": {"A"}, "value": {"100.64.0.9"},
		"view": {"tailnet"}, "csrf_token": {csrf},
	}, c)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("create = %d: %s", rec.Code, rec.Body)
	}
	if !strings.Contains(page(t, h, "/records", c), "tailnet") {
		t.Error("view tag not shown on the records page")
	}
}

func TestRecordDelete(t *testing.T) {
	h, srv, c, csrf := loggedIn(t)
	postForm(t, h, "/records/new", url.Values{
		"name": {"temp.home.arpa."}, "type": {"A"}, "value": {"192.168.1.60"}, "csrf_token": {csrf},
	}, c)
	recs, err := srv.o.Registry.Records()
	if err != nil || len(recs) != 1 {
		t.Fatalf("Records() = %v, %v", recs, err)
	}
	if got := postForm(t, h, "/records/delete", url.Values{
		"id": {itoa(recs[0].ID)}, "csrf_token": {csrf},
	}, c); got.Code != http.StatusSeeOther {
		t.Fatalf("delete = %d: %s", got.Code, got.Body)
	}
	if strings.Contains(page(t, h, "/records", c), "temp.home.arpa.") {
		t.Error("deleted record still listed")
	}
}
