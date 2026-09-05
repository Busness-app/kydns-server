package backup_test

import (
	"path/filepath"
	"testing"

	"github.com/Busness-app/ky-primitives/recoveryclient/guardtest"
)

// Only the restore command may combine shares or open a suite-sealed capsule. The drill
// opens a capsule sealed to a throwaway key inside the library, not here.
func TestNothingInTheServerDecrypts(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	guardtest.NoDecryptOutside(t, root, map[string][]string{
		filepath.Join("cmd", "kydns", "main.go"): {"run"},
	})
}
