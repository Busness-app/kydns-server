package web

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Busness-app/kydns-server/internal/adminapi"
	"github.com/Busness-app/kydns-server/internal/replica"
	"github.com/Busness-app/kydns-server/internal/store"
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
	// Distinct from every other fixture: an assertion that the screen paired
	// with the configured address cannot be satisfied by a peer's address.
	primaryNodeIDFixture = "aabbccdd11223344"
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

// joinCall is one pairing attempt as the joiner received it, so a test can
// prove which address the screen paired with rather than only that it paired.
type joinCall struct{ Address, Code, Fingerprint string }

// fakeJoiner is the replica half of pairing. It compares the fingerprint the
// way the real joiner does, so a mismatch here fails for the real reason.
type fakeJoiner struct {
	presents string // what the node at the far end actually shows
	status   *ReplicaStatus
	calls    []joinCall
}

func (f *fakeJoiner) Peek(_ context.Context, _ string) (string, error) {
	return f.presents, nil
}

func (f *fakeJoiner) Join(_ context.Context, address, code, fingerprint string) (string, error) {
	f.calls = append(f.calls, joinCall{address, code, fingerprint})
	if fingerprint != f.presents {
		return "", fmt.Errorf("%w: %s presented %s", replica.ErrFingerprintRejected, address, f.presents)
	}
	f.status.Paired = true
	return primaryNodeIDFixture, nil
}

// replicationWeb wires a logged-in server whose API carries the replica
// surface, behind the real web write gate. fingerprint is a pointer so a test
// can prove the screen reads this node's key rather than a fixed string.
func replicationWeb(t *testing.T, st *ReplicaStatus, fingerprint *string,
	admin *fakeReplicaAdmin, prom *fakePromoter,
) (http.Handler, *Server, *http.Cookie, string, *bytes.Buffer) {
	t.Helper()
	return replicationWebJoining(t, st, fingerprint, admin, prom, nil)
}

// replicationWebJoining is replicationWeb with the pairing surface attached.
func replicationWebJoining(t *testing.T, st *ReplicaStatus, fingerprint *string,
	admin *fakeReplicaAdmin, prom *fakePromoter, joiner *fakeJoiner,
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
		if joiner != nil {
			api = api.WithReplicaJoiner(joiner)
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
	st := &ReplicaStatus{Role: roleReplica, PrimaryAddr: replicaPrimaryAddr}
	h, _, c, _, _ := replicationWeb(t, st, &fp, nil, &fakePromoter{status: st})

	// Set after the fixture is built, not before: .Unix() floors and
	// shortDuration truncates, so any delay between the two rolls 45s over to
	// 46s. The closure reads this pointer per request.
	st.LastSyncUnix = time.Now().Add(-45 * time.Second).Unix()
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
	// Nothing is meant to keep this page, so say so: a shared browser's back
	// button would otherwise hand the next person a live credential.
	if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Errorf("Cache-Control = %q on a page holding a pairing code, want no-store", cc)
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
	if rec.Code != http.StatusBadRequest {
		t.Errorf("POST %s unconfirmed = %d, want 400", PathPromote, rec.Code)
	}
	// A button that appears to do nothing is a button an operator clicks again.
	if !strings.Contains(rec.Body.String(), promoteUnconfirmed) {
		t.Errorf("the unconfirmed promote does not say why nothing happened:\n%s", rec.Body)
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

// joiningWeb is an unpaired replica: config names a primary, nothing is
// pinned yet. This is a freshly installed node before its first pairing.
func joiningWeb(t *testing.T, paired bool) (http.Handler, *Server, *fakeJoiner, *http.Cookie, string) {
	t.Helper()
	fp := thisFingerprint
	st := &ReplicaStatus{Role: roleReplica, PrimaryAddr: replicaPrimaryAddr, Paired: paired}
	j := &fakeJoiner{presents: otherFingerprint, status: st}
	h, srv, c, csrf, _ := replicationWebJoining(t, st, &fp, nil, &fakePromoter{status: st}, j)
	return h, srv, j, c, csrf
}

func TestUnpairedReplicaOffersThePairingForm(t *testing.T) {
	h, _, _, c, _ := joiningWeb(t, false)
	body := get(t, h, "/replication", c).Body.String()

	if !strings.Contains(body, `action="`+PathJoin+`"`) {
		t.Fatalf("no pairing form posting to %s:\n%s", PathJoin, body)
	}
	// The address is the config's, shown and not asked for: the puller reads
	// replication.primary, so pairing with anything else pairs a node that
	// then polls a different one forever.
	if !strings.Contains(body, replicaPrimaryAddr) {
		t.Errorf("the pairing form does not name the primary from the config:\n%s", body)
	}
	if regexp.MustCompile(`<input[^>]+name="address"`).MatchString(body) {
		t.Errorf("the pairing form takes a typed address; it must use the configured one:\n%s", body)
	}
	// An unpaired node has nothing to discard, so it must not demand the
	// re-pairing confirmation that would otherwise block a first pairing.
	if strings.Contains(body, joinUnconfirmed) {
		t.Errorf("an unpaired replica is asked to confirm re-pairing:\n%s", body)
	}
}

func TestPairingUsesTheConfiguredAddressAndAsksForARestart(t *testing.T) {
	h, _, j, c, csrf := joiningWeb(t, false)
	rec := postForm(t, h, PathJoin, url.Values{
		"csrf_token": {csrf}, "code": {inviteCode}, "fingerprint": {otherFingerprint},
	}, c)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST %s = %d, want 200:\n%s", PathJoin, rec.Code, rec.Body)
	}
	want := []joinCall{{replicaPrimaryAddr, inviteCode, otherFingerprint}}
	if !slices.Equal(j.calls, want) {
		t.Fatalf("joined with %+v, want %+v", j.calls, want)
	}
	// Pairing alone changes nothing an operator can see: the pull loop is built
	// at startup, so a page that only says "paired" reads as a broken feature.
	if body := rec.Body.String(); !strings.Contains(body, "restart") {
		t.Errorf("the page after pairing does not say a restart is needed:\n%s", body)
	}
	// The code is a live credential for as long as it is unspent.
	if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Errorf("Cache-Control = %q on a page that carried a pairing code, want no-store", cc)
	}
}

func TestPairingRefusesAMismatchedFingerprint(t *testing.T) {
	h, _, _, c, csrf := joiningWeb(t, false)
	rec := postForm(t, h, PathJoin, url.Values{
		"csrf_token": {csrf}, "code": {inviteCode}, "fingerprint": {thisFingerprint},
	}, c)
	if rec.Code != http.StatusConflict {
		t.Fatalf("POST %s with the wrong fingerprint = %d, want 409:\n%s", PathJoin, rec.Code, rec.Body)
	}
	body := rec.Body.String()
	// A mismatch may mean something is answering in the primary's place, so the
	// operator has to be told the code survived rather than left guessing.
	if !strings.Contains(body, joinCodeUnsent) {
		t.Errorf("the mismatch does not say the code was not sent:\n%s", body)
	}
	if !strings.Contains(body, otherFingerprint) {
		t.Errorf("the mismatch does not show what was actually presented:\n%s", body)
	}
}

func TestPairingRequiresAFingerprint(t *testing.T) {
	h, _, j, c, csrf := joiningWeb(t, false)
	rec := postForm(t, h, PathJoin, url.Values{
		"csrf_token": {csrf}, "code": {inviteCode}, "fingerprint": {"  "},
	}, c)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST %s with no fingerprint = %d, want 400:\n%s", PathJoin, rec.Code, rec.Body)
	}
	// Not dialled at all: a blank fingerprint is pairing asked to trust whoever
	// answers, which must fail before the code leaves this node.
	if len(j.calls) != 0 {
		t.Errorf("pairing ran with no fingerprint: %+v", j.calls)
	}
}

func TestRepairingAPairedReplicaNeedsConfirmation(t *testing.T) {
	h, _, j, c, csrf := joiningWeb(t, true)

	rec := postForm(t, h, PathJoin, url.Values{
		"csrf_token": {csrf}, "code": {inviteCode}, "fingerprint": {otherFingerprint},
	}, c)
	if len(j.calls) != 0 {
		t.Fatalf("re-pairing ran unconfirmed: %+v", j.calls)
	}
	if rec.Code != http.StatusBadRequest {
		t.Errorf("unconfirmed re-pair = %d, want 400", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), joinUnconfirmed) {
		t.Errorf("the unconfirmed re-pair does not say why nothing happened:\n%s", rec.Body)
	}

	rec = postForm(t, h, PathJoin, url.Values{
		"csrf_token": {csrf}, "code": {inviteCode},
		"fingerprint": {otherFingerprint}, "confirm": {"yes"},
	}, c)
	if rec.Code != http.StatusOK {
		t.Fatalf("confirmed re-pair = %d, want 200:\n%s", rec.Code, rec.Body)
	}
	if len(j.calls) != 1 {
		t.Fatalf("confirmed re-pair ran %d times, want 1", len(j.calls))
	}
}

// The exemption this feature adds to the replica write gate has to actually
// hold: registered anywhere else, the gate answers the form with 409 and the
// node can never pair.
func TestJoinIsRegisteredAtTheReservedPathAndNotRefused(t *testing.T) {
	h, srv, j, c, csrf := joiningWeb(t, false)

	if routes := registeredPostRoutes(t, srv); !slices.Contains(routes, PathJoin) {
		t.Fatalf("no POST route at %s; the gate would refuse the pairing form: %v", PathJoin, routes)
	}
	rec := postForm(t, h, PathJoin, url.Values{
		"csrf_token": {csrf}, "code": {inviteCode}, "fingerprint": {otherFingerprint},
	}, c)
	if rec.Code == http.StatusConflict {
		t.Fatalf("POST %s = 409 on a replica; the write gate refused pairing:\n%s", PathJoin, rec.Body)
	}
	if len(j.calls) != 1 {
		t.Fatalf("pairing through the gate ran %d times, want 1", len(j.calls))
	}
}

// A replica with no pairing surface wired is a node with no replication
// identity: it must say so rather than render a form that cannot work.
func TestPairingFormAbsentWithNoJoinerWired(t *testing.T) {
	fp := thisFingerprint
	st := &ReplicaStatus{Role: roleReplica, PrimaryAddr: replicaPrimaryAddr}
	h, _, c, csrf, _ := replicationWeb(t, st, &fp, nil, &fakePromoter{status: st})

	if body := get(t, h, "/replication", c).Body.String(); strings.Contains(body, `action="`+PathJoin+`"`) {
		t.Errorf("a node with no pairing surface still shows the form:\n%s", body)
	}
	rec := postForm(t, h, PathJoin, url.Values{
		"csrf_token": {csrf}, "code": {inviteCode}, "fingerprint": {otherFingerprint},
	}, c)
	if rec.Code != http.StatusConflict {
		t.Errorf("POST %s with no joiner = %d, want 409:\n%s", PathJoin, rec.Code, rec.Body)
	}
}

func TestStandaloneNodeHidesTheScreen(t *testing.T) {
	fp := ""
	for _, st := range []*ReplicaStatus{nil, {Role: "standalone"}} {
		h, _, c, csrf, _ := replicationWeb(t, st, &fp, nil, nil)

		// A POST that ends in the redirect must not have written a refusal
		// status first: the operator would get a bare 400 with no page behind it.
		rec := postForm(t, h, PathPromote, url.Values{"csrf_token": {csrf}}, c)
		if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/" {
			t.Errorf("POST %s on a standalone node = %d to %q, want 303 to /:\n%s",
				PathPromote, rec.Code, rec.Header().Get("Location"), rec.Body)
		}

		if body := get(t, h, "/", c).Body.String(); strings.Contains(body, `href="/replication"`) {
			t.Errorf("a standalone node shows the Replication nav entry:\n%s", body)
		}
		rec = get(t, h, "/replication", c)
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
	st := &ReplicaStatus{Role: roleReplica, PrimaryAddr: replicaPrimaryAddr}
	h, _, c, _, _ := replicationWeb(t, st, &fp, nil, &fakePromoter{status: st})

	// Set immediately before the request: see the note in the replica screen
	// test. Login runs argon2id, which is long enough to cross the second.
	st.LastSyncUnix = time.Now().Add(-45 * time.Second).Unix()
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
