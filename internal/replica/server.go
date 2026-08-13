package replica

import (
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"time"

	"github.com/yoshiofthewire/kydns-server/internal/store"
)

// PeerStore is the pinned set: membership is the whole access control.
type PeerStore interface {
	Peer(nodeID string) (store.Peer, error)
	Peers() ([]store.Peer, error)
	TouchPeer(nodeID string, syncedAt, version int64) error
}

// Source reads what a replica pulls. Snapshot returns the version and the
// configuration together so the two can never disagree.
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
	http  *http.Server
}

func NewServer(id *Identity, peers PeerStore, src Source, book *InviteBook) *Server {
	s := &Server{id: id, peers: peers, src: src, book: book}
	mux := http.NewServeMux()
	// Replication is read-only; the mux answers any other method with 405.
	mux.HandleFunc("GET /replica/version", s.requirePinned(s.handleVersion))
	mux.HandleFunc("GET /replica/snapshot", s.requirePinned(s.handleSnapshot))
	s.http = &http.Server{Handler: mux, ReadHeaderTimeout: requestTimeout}
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

// requirePinned refuses peers that are not paired. Pairing is the one route
// that will register itself without this wrapper.
func (s *Server) requirePinned(h func(w http.ResponseWriter, r *http.Request, fp string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fp, ok := peerFingerprint(r)
		if !ok {
			http.Error(w, "no peer certificate", http.StatusForbidden)
			return
		}
		if _, err := s.peers.Peer(fp); err != nil {
			http.Error(w, "peer is not paired", http.StatusForbidden)
			return
		}
		h(w, r, fp)
	}
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

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request, fp string) {
	v, err := s.src.Version()
	if err != nil {
		http.Error(w, "version unavailable", http.StatusInternalServerError)
		return
	}
	s.write(w, fp, v.ConfigVersion, v)
}

func (s *Server) handleSnapshot(w http.ResponseWriter, r *http.Request, fp string) {
	snap, err := s.src.Snapshot()
	if err != nil {
		http.Error(w, "snapshot unavailable", http.StatusInternalServerError)
		return
	}
	s.write(w, fp, snap.ConfigVersion, snap)
}

func (s *Server) write(w http.ResponseWriter, fp string, version int64, body any) {
	// Last-seen bookkeeping only; a failure here must not fail the pull.
	_ = s.peers.TouchPeer(fp, time.Now().Unix(), version)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(body)
}
