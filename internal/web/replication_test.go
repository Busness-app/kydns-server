package web

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/yoshiofthewire/kydns-server/internal/adminapi"
	"github.com/yoshiofthewire/kydns-server/internal/store"
)

// The fixtures are chosen so no assertion can be satisfied by another's value:
// no label is a substring of a node ID, no address repeats, and the lag is a
// number that appears nowhere else on the page.
const (
	peerOneID    = "1a2b3c4d5e6f7081"
	peerOneLabel = "kitchen-shed"
	peerOneAddr  = "203.0.113.41:9443"
	peerTwoID    = "9988776655443322"
	peerTwoLabel = "attic-relay"
	peerTwoAddr  = "203.0.113.77:9443"

	primaryVersion = int64(5127)
	peerOneVersion = int64(5000)
	peerOneLag     = "127"

	thisFingerprint  = "a1b2c3d4e5f60718293a4b5c6d7e8f90"
	otherFingerprint = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"

	inviteCode = "quiet-otter-lantern-42"

	replicaPrimaryAddr = "198.51.100.7:9443"
)

// fakeReplicaAdmin is the primary half. The web layer must go through
// adminapi to reach it, so what this records is what the screen actually
// asked the shared handlers to do.
type fakeReplicaAdmin struct {
	peers    []store.Peer
	version  int64
	code     string
	expires  time.Time
	inviteEr error
	unpaired []string
}

func (f *fakeReplicaAdmin) Invite() (string, time.Time, error) {
	if f.inviteEr != nil {
		return "", time.Time{}, f.inviteEr
	}
	return f.code, f.expires, nil
}
func (f *fakeReplicaAdmin) Peers() ([]store.Peer, error)  { return f.peers, nil }
func (f *fakeReplicaAdmin) ConfigVersion() (int64, error) { return f.version, nil }
func (f *fakeReplicaAdmin) Unpair(nodeID string) error {
	f.unpaired = append(f.unpaired, nodeID)
	return nil
}

func twoPeers(now time.Time) *fakeReplicaAdmin {
	return &fakeReplicaAdmin{
		version: primaryVersion,
		code:    inviteCode,
		expires: now.Add(10 * time.Minute),
		peers: []store.Peer{
			{
				NodeID: peerOneID, Label: peerOneLabel, Address: peerOneAddr,
				LastSyncAt: now.Add(-125 * time.Minute).Unix(), LastVersion: peerOneVersion,
			},
			{NodeID: peerTwoID, Label: peerTwoLabel, Address: peerTwoAddr},
		},
	}
}

// fakePromoter flips the shared status the way the real promoter flips the
// live role, so the page rendered after a promotion is the one an operator
// would actually be handed.
type fakePromoter struct {
	status *ReplicaStatus
	calls  int
}

func (f *fakePromoter) Promote() (bool, error) {
	f.calls++
	if f.status.Role != roleReplica {
		return false, nil
	}
	f.status.Role, f.status.PrimaryAddr = "primary", ""
	return true, nil
}

// replicationWeb wires a logged-in server whose API carries the replica
// surface, behind the real web write gate. fingerprint is a pointer so a test
// can prove the screen reads this node's key rather than a fixed string.
func replicationWeb(t *testing.T, st *ReplicaStatus, fingerprint *string,
	admin *fakeReplicaAdmin, prom *fakePromoter,
) (http.Handler, *Server, *http.Cookie, string, *bytes.Buffer) {
	t.Helper()
	var logs bytes.Buffer
	mux, srv := newWeb(t, func(o *Options) {
		o.Logger = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
		if st != nil {
			o.Replication = func() ReplicaStatus { return *st }
		}
		api := o.API.WithReplication(func() adminapi.ReplicaStatus {
			var cur ReplicaStatus
			if st != nil {
				cur = *st
			}
			return adminapi.ReplicaStatus{
				Role: cur.Role, PrimaryAddr: cur.PrimaryAddr,
				NodeID: *fingerprint, LastSyncUnix: cur.LastSyncUnix,
			}
		})
		if admin != nil {
			api = api.WithReplicaAdmin(admin)
		}
		if prom != nil {
			api = api.WithReplicaPromoter(prom)
		}
		o.API = api
	})
	h := srv.WriteGate(mux)
	setupAndLogin(t, h)
	c := loginCookie(t, h)
	sess, ok := srv.o.Sessions.Get(c.Value)
	if !ok {
		t.Fatal("no session")
	}
	return h, srv, c, sess.CSRF, &logs
}

// primaryWeb is a node serving the two fixture peers.
func primaryWeb(t *testing.T) (http.Handler, *fakeReplicaAdmin, *string, *http.Cookie, string, *bytes.Buffer) {
	t.Helper()
	admin := twoPeers(time.Now())
	fp := thisFingerprint
	st := &ReplicaStatus{Role: "primary"}
	h, _, c, csrf, logs := replicationWeb(t, st, &fp, admin, nil)
	return h, admin, &fp, c, csrf, logs
}

// rowFor returns the table row holding needle, so an assertion about one peer
// cannot be satisfied by another peer's cell.
func rowFor(t *testing.T, body, needle string) string {
	t.Helper()
	for _, row := range strings.Split(body, "<tr") {
		if strings.Contains(row, needle) {
			return row
		}
	}
	t.Fatalf("no row containing %q:\n%s", needle, body)
	return ""
}

func TestPrimaryReplicasScreenListsPeers(t *testing.T) {
	h, _, _, c, _, _ := primaryWeb(t)
	rec := get(t, h, "/replication", c)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /replication on a primary = %d, want 200:\n%s", rec.Code, rec.Body)
	}
	body := rec.Body.String()

	one := rowFor(t, body, peerOneLabel)
	for _, want := range []string{peerOneID, peerOneAddr, peerOneLag, "2h ago", ">behind<"} {
		if !strings.Contains(one, want) {
			t.Errorf("the %s row is missing %q:\n%s", peerOneLabel, want, one)
		}
	}

	two := rowFor(t, body, peerTwoLabel)
	if !strings.Contains(two, ">never synced<") {
		t.Errorf("the %s row does not say it has never synced:\n%s", peerTwoLabel, two)
	}
	// A peer that never answered has no age and no meaningful lag; showing a
	// number there reads as a replica that is merely a little behind.
	if !strings.Contains(two, ">never<") {
		t.Errorf("the %s row does not render its last sync as never:\n%s", peerTwoLabel, two)
	}
	if strings.Contains(two, strconv.FormatInt(primaryVersion, 10)) {
		t.Errorf("the %s row shows a version lag for a peer that never synced:\n%s", peerTwoLabel, two)
	}
	if strings.Contains(two, "1970") {
		t.Errorf("the %s row renders the epoch as a date:\n%s", peerTwoLabel, two)
	}

	if !strings.Contains(body, "Add replica") {
		t.Errorf("a primary has no Add replica control:\n%s", body)
	}
	// Removal is per peer, so the node ID has to travel with the button.
	if !strings.Contains(rowFor(t, body, peerTwoLabel), `value="`+peerTwoID+`"`) {
		t.Errorf("the %s row has no remove control carrying its node ID:\n%s", peerTwoLabel, two)
	}
}

func TestRemoveControlUnpairsThatPeer(t *testing.T) {
	h, admin, _, c, csrf, _ := primaryWeb(t)
	rec := postForm(t, h, "/replication/remove", url.Values{
		"csrf_token": {csrf}, "node_id": {peerTwoID},
	}, c)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("POST /replication/remove = %d, want 303:\n%s", rec.Code, rec.Body)
	}
	if !slices.Equal(admin.unpaired, []string{peerTwoID}) {
		t.Errorf("unpaired = %v, want exactly [%s]", admin.unpaired, peerTwoID)
	}
}

func TestReplicaScreenNamesItsPrimaryAndSyncAge(t *testing.T) {
	fp := thisFingerprint
	st := &ReplicaStatus{
		Role: roleReplica, PrimaryAddr: replicaPrimaryAddr,
		LastSyncUnix: time.Now().Add(-45 * time.Second).Unix(),
	}
	h, _, c, _, _ := replicationWeb(t, st, &fp, nil, &fakePromoter{status: st})

	rec := get(t, h, "/replication", c)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /replication on a replica = %d, want 200:\n%s", rec.Code, rec.Body)
	}
	body := rec.Body.String()
	if !strings.Contains(body, replicaPrimaryAddr) {
		t.Errorf("the replica screen does not name the primary it follows:\n%s", body)
	}
	if !strings.Contains(body, "45s ago") {
		t.Errorf("the replica screen does not say how long since the last sync:\n%s", body)
	}
	if strings.Contains(body, "1970") {
		t.Errorf("the replica screen renders a timestamp as an epoch date:\n%s", body)
	}
	// Minting invites is the primary's job, and a replica that offers it hands
	// out codes for peers its primary knows nothing about.
	if strings.Contains(body, "Add replica") {
		t.Errorf("a replica offers the Add replica control:\n%s", body)
	}
}

var (
	inviteBlock  = regexp.MustCompile(`(?s)<table class="grid invite">(.*?)</table>`)
	inviteFPCell = regexp.MustCompile(`data-invite="fingerprint">([^<]+)<`)
)

func TestInviteDisplaysCodeAndFingerprintTogether(t *testing.T) {
	h, _, fp, c, csrf, logs := primaryWeb(t)

	rec := postForm(t, h, "/replication/invite", url.Values{"csrf_token": {csrf}}, c)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /replication/invite = %d, want 200:\n%s", rec.Code, rec.Body)
	}
	body := rec.Body.String()

	m := inviteBlock.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no invite block on the page:\n%s", body)
	}
	block := m[1]
	if !strings.Contains(block, inviteCode) {
		t.Errorf("the invite block does not show the code:\n%s", block)
	}
	// Together, in one block: a code shown without the fingerprint beside it
	// leaves the operator nothing to compare on the other machine.
	if !strings.Contains(block, thisFingerprint) {
		t.Errorf("the invite block does not show this node's fingerprint:\n%s", block)
	}

	shown := inviteFPCell.FindStringSubmatch(block)
	if shown == nil {
		t.Fatalf("no fingerprint cell in the invite block:\n%s", block)
	}
	if shown[1] != thisFingerprint {
		t.Errorf("fingerprint shown = %q, want this node's %q", shown[1], thisFingerprint)
	}

	// Not any non-empty string: change the node's key and the screen must
	// follow it, which a hardcoded or borrowed value would not.
	*fp = otherFingerprint
	rec = postForm(t, h, "/replication/invite", url.Values{"csrf_token": {csrf}}, c)
	block = inviteBlock.FindStringSubmatch(rec.Body.String())[1]
	shown = inviteFPCell.FindStringSubmatch(block)
	if shown == nil || shown[1] != otherFingerprint {
		t.Errorf("fingerprint shown = %v after the node's key changed, want %q", shown, otherFingerprint)
	}
	if strings.Contains(block, thisFingerprint) {
		t.Errorf("the invite block still shows the old fingerprint:\n%s", block)
	}

	// The code is a credential: it belongs in the response body and nowhere
	// else. Not in a redirect, not in the log.
	if loc := rec.Header().Get("Location"); loc != "" {
		t.Errorf("the invite response redirects to %q; a code must not travel in a URL", loc)
	}
	if strings.Contains(logs.String(), inviteCode) {
		t.Errorf("the pairing code was written to the log:\n%s", logs)
	}
}

// The two halves of the warning: what the operator must do to the old primary,
// and why there is no recovering from not doing it.
const (
	promoteWarningDo  = "demoted or rebuilt"
	promoteWarningWhy = "two primaries"
)

func TestPromoteButtonCarriesTheWarning(t *testing.T) {
	fp := thisFingerprint
	st := &ReplicaStatus{Role: roleReplica, PrimaryAddr: replicaPrimaryAddr, LastSyncUnix: time.Now().Unix()}
	prom := &fakePromoter{status: st}
	h, _, c, csrf, _ := replicationWeb(t, st, &fp, nil, prom)

	body := get(t, h, "/replication", c).Body.String()
	for _, want := range []string{promoteWarningDo, promoteWarningWhy} {
		if !strings.Contains(body, want) {
			t.Errorf("the promote confirmation does not carry %q:\n%s", want, body)
		}
	}

	// The button posts to the reserved path. Anywhere else and the gate answers
	// the click with 409, in the outage promotion exists for.
	if !strings.Contains(body, `action="`+PathPromote+`"`) {
		t.Errorf("the promote form does not post to %s:\n%s", PathPromote, body)
	}

	// Unconfirmed is not promoted: this is the one state the design cannot undo.
	rec := postForm(t, h, PathPromote, url.Values{"csrf_token": {csrf}}, c)
	if prom.calls != 0 {
		t.Fatalf("promotion ran with no confirmation (%d calls), status %d", prom.calls, rec.Code)
	}
	if st.Role != roleReplica {
		t.Fatalf("role = %q after an unconfirmed promote, want replica", st.Role)
	}

	rec = postForm(t, h, PathPromote, url.Values{"csrf_token": {csrf}, "confirm": {"yes"}}, c)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST %s confirmed = %d, want 200:\n%s", PathPromote, rec.Code, rec.Body)
	}
	if prom.calls != 1 {
		t.Fatalf("confirmed promote ran %d times, want 1", prom.calls)
	}
	body = rec.Body.String()
	// What to do next, not just what happened: a promoted node serves no
	// replicas until the listener is configured and it is restarted.
	for _, want := range []string{"replication.listen", "restart", promoteWarningDo} {
		if !strings.Contains(body, want) {
			t.Errorf("the page after promoting does not say %q:\n%s", want, body)
		}
	}
}

// Ruling 5: the button must be registered at the one path the web write gate
// reserved. Anywhere else and the gate refuses it with 409, in the outage it
// exists for.
func TestPromoteIsRegisteredAtTheReservedPathAndNotRefused(t *testing.T) {
	fp := thisFingerprint
	st := &ReplicaStatus{Role: roleReplica, PrimaryAddr: replicaPrimaryAddr, LastSyncUnix: time.Now().Unix()}
	prom := &fakePromoter{status: st}
	h, srv, c, csrf, _ := replicationWeb(t, st, &fp, nil, prom)

	if routes := registeredPostRoutes(t, srv); !slices.Contains(routes, PathPromote) {
		t.Fatalf("no POST route at %s; the gate would refuse whatever path the button uses: %v", PathPromote, routes)
	}
	rec := postForm(t, h, PathPromote, url.Values{"csrf_token": {csrf}, "confirm": {"yes"}}, c)
	if rec.Code == http.StatusConflict {
		t.Fatalf("POST %s = 409 on a replica:\n%s", PathPromote, rec.Body)
	}
	if prom.calls != 1 || st.Role != "primary" {
		t.Fatalf("promote through the gate ran %d times, role = %q", prom.calls, st.Role)
	}
}

func TestStandaloneNodeHidesTheScreen(t *testing.T) {
	fp := ""
	for _, st := range []*ReplicaStatus{nil, {Role: "standalone"}} {
		h, _, c, _, _ := replicationWeb(t, st, &fp, nil, nil)

		if body := get(t, h, "/", c).Body.String(); strings.Contains(body, `href="/replication"`) {
			t.Errorf("a standalone node shows the Replication nav entry:\n%s", body)
		}
		rec := get(t, h, "/replication", c)
		if rec.Code != http.StatusSeeOther {
			t.Errorf("GET /replication on a standalone node = %d, want 303:\n%s", rec.Code, rec.Body)
		}
		if loc := rec.Header().Get("Location"); loc != "/" {
			t.Errorf("GET /replication on a standalone node went to %q, want /", loc)
		}
	}

	h, _, _, c, _, _ := primaryWeb(t)
	if body := get(t, h, "/", c).Body.String(); !strings.Contains(body, `href="/replication"`) {
		t.Errorf("a primary has no Replication nav entry:\n%s", body)
	}
}

var (
	dashRole   = regexp.MustCompile(`data-stat="role">([^<]*)<`)
	dashDetail = regexp.MustCompile(`data-stat="replication">([^<]*)<`)
)

func dashboardReplication(t *testing.T, h http.Handler, c *http.Cookie) (string, string) {
	t.Helper()
	body := get(t, h, "/", c).Body.String()
	role, detail := dashRole.FindStringSubmatch(body), dashDetail.FindStringSubmatch(body)
	if role == nil || detail == nil {
		t.Fatalf("no replication line on the dashboard:\n%s", body)
	}
	return role[1], detail[1]
}

func TestDashboardLineNamesTheRoleAndPeerCount(t *testing.T) {
	h, _, _, c, _, _ := primaryWeb(t)
	role, detail := dashboardReplication(t, h, c)
	if role != "primary" {
		t.Errorf("dashboard role = %q, want primary", role)
	}
	if detail != "2 replicas" {
		t.Errorf("dashboard detail = %q, want the peer count", detail)
	}
}

func TestDashboardLineOnAReplicaShowsSyncAge(t *testing.T) {
	fp := thisFingerprint
	st := &ReplicaStatus{
		Role: roleReplica, PrimaryAddr: replicaPrimaryAddr,
		LastSyncUnix: time.Now().Add(-45 * time.Second).Unix(),
	}
	h, _, c, _, _ := replicationWeb(t, st, &fp, nil, &fakePromoter{status: st})
	role, detail := dashboardReplication(t, h, c)
	if role != roleReplica {
		t.Errorf("dashboard role = %q, want replica", role)
	}
	if detail != "synced 45s ago" {
		t.Errorf("dashboard detail = %q, want the sync age", detail)
	}
}

// A standalone node has no role to report, so the line is absent rather than
// present and empty.
func TestDashboardHasNoReplicationLineWhenStandalone(t *testing.T) {
	h, _ := newWeb(t)
	setupAndLogin(t, h)
	c := loginCookie(t, h)
	if body := get(t, h, "/", c).Body.String(); dashRole.MatchString(body) {
		t.Errorf("a standalone node shows a replication line:\n%s", body)
	}
}
