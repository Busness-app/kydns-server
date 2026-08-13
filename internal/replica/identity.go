package replica

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const keyFile = "node_key"

// Identity is this node's long-lived keypair. The node ID is the public key's
// fingerprint, so identity is the key itself rather than a name two operators
// could pick the same way.
type Identity struct {
	PrivateKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey
	NodeID     string
}

// Fingerprint is the peer identifier shown to operators and pinned at pairing.
func Fingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])
}

// LoadOrCreateIdentity reads data_dir/node_key, generating it on first use. A
// key that exists but cannot be parsed is an error: silently replacing it
// would change this node's identity and make every paired peer refuse it.
func LoadOrCreateIdentity(dataDir string) (*Identity, error) {
	path := filepath.Join(dataDir, keyFile)
	seed, err := os.ReadFile(path)
	switch {
	case err == nil:
		if len(seed) != ed25519.SeedSize {
			return nil, fmt.Errorf("%s: want %d bytes, found %d", path, ed25519.SeedSize, len(seed))
		}
	case errors.Is(err, os.ErrNotExist):
		seed = make([]byte, ed25519.SeedSize)
		if _, err := rand.Read(seed); err != nil {
			return nil, err
		}
		if err := os.WriteFile(path, seed, 0o600); err != nil {
			return nil, fmt.Errorf("write %s: %w", path, err)
		}
	default:
		return nil, err
	}

	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	return &Identity{PrivateKey: priv, PublicKey: pub, NodeID: Fingerprint(pub)}, nil
}
