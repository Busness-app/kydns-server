package replica

import (
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/yoshiofthewire/kydns-server/internal/store"
)

// PeerStore is the pinned set: membership is the whole access control.
type PeerStore interface {
	Peer(nodeID string) (store.Peer, error)
	Peers() ([]store.Peer, error)
	PutPeer(p store.Peer) error
	TouchPeer(nodeID string, syncedAt int64, version *int64) error
}

// Source reads what a replica pulls. Snapshot reads the version first, so a
// write landing mid-read ships a body newer than the version it carries and
// the replica pulls again next tick; the other order would strand it.
type Source interface {
	Version() (VersionReply, error)
	Snapshot() (Snapshot, error)
}

// Server serves /replica/version and /replica/snapshot over TLS to peers whose
// fingerprint is in peers.
type Server struct {
	id    *Identity
	peers PeerStore
	src   Source
	book  *InviteBook
	mux   *http.ServeMux
	http  *http.Server
}

// unpinnedPaths is the entire list of routes an unpaired peer may reach.
// Pairing is on it because pairing is how a peer becomes pinned; the handler
// arrives with the pairing route.
var unpinnedPaths = map[string]bool{"/replica/pair": true}

func NewServer(id *Identity, peers PeerStore, src Source, book *InviteBook) *Server {
	s := &Server{id: id, peers: peers, src: src, book: book, mux: http.NewServeMux()}
	// Replication is read-only; the mux answers any other method with 405.
	s.mux.HandleFunc("GET /replica/version", s.handleVersion)
	s.mux.HandleFunc("GET /replica/snapshot", s.handleSnapshot)
	s.mux.HandleFunc("POST /replica/pair", s.handlePair)
	s.http = &http.Server{
		Handler:           s.pinnedExcept(s.mux),
		ReadHeaderTimeout: requestTimeout,
		WriteTimeout:      requestTimeout,
		// A peer that completes a handshake and then goes quiet costs a goroutine
		// and a connection until this fires.
		IdleTimeout: 60 * time.Second,
	}
	return s
}

func (s *Server) Serve(l net.Listener) error {
	// The handshake accepts any Ed25519 peer and the routes decide who gets an
	// answer, because pairing has to be reachable by a peer not yet pinned.
	cfg, err := pinnedTLSConfig(s.id, func(string) bool { return true })
	if err != nil {
		return err
	}
	return s.http.Serve(tls.NewListener(l, cfg))
}

func (s *Server) Close() error { return s.http.Close() }

// pinnedExcept guards every route, so a handler added later fails closed
// rather than being reachable by anyone holding a self-signed key. An
// unpinned peer is answered the same way whatever it asks for, which also
// keeps it from learning which routes exist.
func (s *Server) pinnedExcept(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if unpinnedPaths[r.URL.Path] {
			h.ServeHTTP(w, r)
			return
		}
		fp, ok := peerFingerprint(r)
		if !ok {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if _, err := s.peers.Peer(fp); err != nil {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// peerFingerprint is the identity the handshake verified for this connection.
// The pin check already rejected anything that is not an Ed25519 leaf.
func peerFingerprint(r *http.Request) (string, bool) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return "", false
	}
	pub, ok := r.TLS.PeerCertificates[0].PublicKey.(ed25519.PublicKey)
	if !ok {
		return "", false
	}
	return Fingerprint(pub), true
}

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	v, err := s.src.Version()
	if err != nil {
		http.Error(w, "version unavailable", http.StatusInternalServerError)
		return
	}
	s.write(w, r, v)
}

func (s *Server) handleSnapshot(w http.ResponseWriter, r *http.Request) {
	snap, err := s.src.Snapshot()
	if err != nil {
		http.Error(w, "snapshot unavailable", http.StatusInternalServerError)
		return
	}
	s.write(w, r, snap)
}

func (s *Server) write(w http.ResponseWriter, r *http.Request, body any) {
	// Last-seen bookkeeping only; a failure here must not fail the pull.
	if fp, ok := peerFingerprint(r); ok {
		_ = s.peers.TouchPeer(fp, time.Now().Unix(), reportedVersion(r))
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(body)
}

// reportedVersion is the version the replica says it holds, which is the only
// side that knows it. Nil when it said nothing, so an older replica still
// records a last-seen time.
func reportedVersion(r *http.Request) *int64 {
	q := r.URL.Query().Get("version")
	if q == "" {
		return nil
	}
	v, err := strconv.ParseInt(q, 10, 64)
	if err != nil {
		return nil
	}
	return &v
}
