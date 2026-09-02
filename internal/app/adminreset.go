package app

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/term"

	"github.com/Busness-app/kydns-server/internal/auth"
	"github.com/Busness-app/kydns-server/internal/config"
	"github.com/Busness-app/kydns-server/internal/store"
)

// PasswordReader collects a password. Injected so the reset flow is testable
// without a terminal.
type PasswordReader func(prompt string) (string, error)

// ResetAdminPassword sets the admin password by opening the database directly.
//
// This is the one command that bypasses the admin API, and it exists because
// there is otherwise no way back in after a forgotten password. It is safe to
// leave unauthenticated: it requires write access to the database file, and
// anyone with that can already read every hash and token in it.
func ResetAdminPassword(cfgPath string, read PasswordReader, out io.Writer) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	dbPath := filepath.Join(cfg.DataDir, "kydns.db")
	if _, err := os.Stat(dbPath); err != nil {
		return fmt.Errorf("no database at %s: has KyDNS ever run?", dbPath)
	}
	st, err := store.Open(dbPath)
	if err != nil {
		return err
	}
	defer st.Close()

	password, err := read("New admin password: ")
	if err != nil {
		return err
	}
	if len(password) < auth.MinPasswordLen {
		return fmt.Errorf("password must be at least %d characters", auth.MinPasswordLen)
	}
	confirm, err := read("Confirm password: ")
	if err != nil {
		return err
	}
	if password != confirm {
		return errors.New("the two passwords do not match")
	}

	hash, err := auth.HashPassword(password)
	if err != nil {
		return err
	}
	if err := st.SetAdminPassword(hash); err != nil {
		return err
	}

	fmt.Fprintf(out, "Admin password updated in %s.\n", dbPath)
	// Sessions live in the running process's memory, so a reset performed
	// against a live server does not end them.
	fmt.Fprintln(out, "Restart KyDNS to end any signed-in sessions.")
	return nil
}

// stdinReader is shared across calls. A fresh bufio.Reader per prompt would
// discard whatever the first read buffered, so the second line of a piped
// password would never arrive.
var stdinReader *bufio.Reader

// TerminalPassword reads without echoing when stdin is a terminal, and falls
// back to a plain line so the command stays scriptable:
//
//	printf 'newpassword\nnewpassword\n' | kydns admin reset-password
func TerminalPassword(prompt string) (string, error) {
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		fmt.Fprint(os.Stderr, prompt)
		raw, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", err
		}
		return string(raw), nil
	}
	if stdinReader == nil {
		stdinReader = bufio.NewReader(os.Stdin)
	}
	line, err := stdinReader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}
