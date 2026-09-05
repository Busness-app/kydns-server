package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"strconv"
	"time"

	"github.com/Busness-app/ky-primitives/recoveryclient"
	"github.com/Busness-app/kydns-server/internal/backup"
	"github.com/Busness-app/kydns-server/internal/store"
)

// backupMessage is the operator-facing sentence for a library error. It repeats
// adminapi.backupStatusCode's wording deliberately: that function is unexported and
// adminapi imports nothing from web, so the alternative is a shared package for six
// strings. The two transports must say the same thing, so a change here is a change
// there; the API tests pin the wording on their side.
func backupMessage(err error) string {
	switch {
	case errors.Is(err, recoveryclient.ErrKeyPinMissing):
		return "paired but the recovery public key is missing or does not match the pin; restore recovery.pub or re-pair"
	case errors.Is(err, recoveryclient.ErrNotPaired):
		return "no recovery key: pair with KyRecovery or pin the suite key first"
	case errors.Is(err, recoveryclient.ErrNoDestination):
		return "nowhere to put a capsule: pair with KyRecovery or set KYDNS_BACKUP_DIR"
	case errors.Is(err, recoveryclient.ErrKeyMismatch), errors.Is(err, fs.ErrExist):
		return "already pinned to a different recovery key"
	case errors.Is(err, recoveryclient.ErrInProgress):
		return "a backup is already in progress"
	default:
		return recoveryclient.AuditSafe(err.Error())
	}
}

// backupError re-renders the settings screen with the failure. Every backup failure is
// something the operator can act on from this page, so it is 400 and the page, not a
// bare status code on a blank tab.
func (s *Server) backupError(w http.ResponseWriter, r *http.Request, err error) {
	w.WriteHeader(http.StatusBadRequest)
	s.render(w, r, "settings.html", s.settingsData(backupMessage(err), ""))
}

// auditBackup records one attempt. outcome follows err, so a refusal leaves the same
// trail as a success.
func (s *Server) auditBackup(b *backup.Service, r *http.Request, action, resource, details string, err error) {
	outcome := "success"
	if err != nil {
		outcome = "failure"
		details += " " + err.Error()
	}
	_ = b.Store.RecordAudit(store.AuditEvent{Actor: "admin", Action: action,
		Resource: recoveryclient.AuditSafe(resource), Details: recoveryclient.AuditSafe(details),
		IP: recoveryclient.AuditSafe(r.RemoteAddr), Outcome: outcome})
}

// pairURLError mirrors adminapi.pairURLError: the library's rule, with this product's
// switch named only when setting it would actually admit this URL.
func pairURLError(raw string, allowPrivate bool) error {
	err := recoveryclient.ValidateURL(raw, allowPrivate)
	if err == nil || allowPrivate {
		return err
	}
	if recoveryclient.ValidateURL(raw, true) == nil {
		return fmt.Errorf("%w; set KYDNS_BACKUP_ALLOW_PRIVATE_RECOVERY for a KyRecovery on your own network", err)
	}
	return err
}

func (s *Server) postBackupPair(w http.ResponseWriter, r *http.Request) {
	b := s.o.Backup
	if b == nil {
		s.backupError(w, r, errors.New("backup service is unavailable"))
		return
	}
	u, code := r.PostFormValue("recovery_url"), r.PostFormValue("pairing_code")
	allow := " allow_private=" + strconv.FormatBool(b.Cfg.BackupAllowPrivateRecovery)
	// Checked before the claim, so a URL this node would never deposit to is refused
	// without presenting the pairing code to it. The refusal is audited like any other.
	if err := pairURLError(u, b.Cfg.BackupAllowPrivateRecovery); err != nil {
		s.auditBackup(b, r, "backup.paired", "", u+allow, err)
		s.backupError(w, r, err)
		return
	}
	key, err := b.Pair(r.Context(), u, code)
	s.auditBackup(b, r, "backup.paired", key.Public.ID(), u+allow, err)
	if err != nil {
		s.backupError(w, r, err)
		return
	}
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

func (s *Server) postBackupPinKey(w http.ResponseWriter, r *http.Request) {
	b := s.o.Backup
	if b == nil {
		s.backupError(w, r, errors.New("backup service is unavailable"))
		return
	}
	k, errK := strconv.Atoi(r.PostFormValue("threshold"))
	n, errN := strconv.Atoi(r.PostFormValue("total_shares"))
	if errK != nil || errN != nil {
		err := errors.New("threshold and total shares must be numbers")
		s.auditBackup(b, r, "backup.key_pinned", "", r.PostFormValue("threshold")+"/"+r.PostFormValue("total_shares"), err)
		s.backupError(w, r, err)
		return
	}
	key, err := b.PinKey(r.PostFormValue("public_key"), k, n)
	s.auditBackup(b, r, "backup.key_pinned", key.Public.ID(), fmt.Sprintf("%d-of-%d", k, n), err)
	if err != nil {
		s.backupError(w, r, err)
		return
	}
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

func (s *Server) postBackupUnpair(w http.ResponseWriter, r *http.Request) {
	b := s.o.Backup
	if b == nil {
		s.backupError(w, r, errors.New("backup service is unavailable"))
		return
	}
	err := b.Unpair()
	s.auditBackup(b, r, "backup.unpaired", "", "url and sealed token rows removed; key pin kept", err)
	if err != nil {
		s.backupError(w, r, err)
		return
	}
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

func (s *Server) postBackupSchedule(w http.ResponseWriter, r *http.Request) {
	b := s.o.Backup
	if b == nil {
		s.backupError(w, r, errors.New("backup service is unavailable"))
		return
	}
	minutes, err := strconv.ParseInt(r.PostFormValue("interval_minutes"), 10, 64)
	if err != nil || minutes < 0 || minutes > int64(recoveryclient.MaxInterval/time.Minute) {
		s.auditBackup(b, r, "backup.schedule", "", r.PostFormValue("interval_minutes"), recoveryclient.ErrBadInterval)
		s.backupError(w, r, recoveryclient.ErrBadInterval)
		return
	}
	got, err := b.SetSchedule(minutes * 60)
	// The stored value read back, not the request: the audit row says what the
	// scheduler will actually do.
	s.auditBackup(b, r, "backup.schedule", "", strconv.FormatInt(int64(got/time.Second), 10), err)
	if err != nil {
		s.backupError(w, r, err)
		return
	}
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}
func (s *Server) postBackupDeposit(w http.ResponseWriter, r *http.Request) {
	b := s.o.Backup
	if b == nil {
		s.backupError(w, r, errors.New("backup service is unavailable"))
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 16*time.Minute)
	defer cancel()
	res, err := b.Run(ctx)
	action, outcome, details := recoveryclient.Outcome(res, err)
	raw, _ := json.Marshal(details)
	_ = b.Store.RecordAudit(store.AuditEvent{Actor: "admin", Action: action,
		Resource: recoveryclient.AuditSafe(res.Manifest.CapsuleID), Details: string(raw),
		IP: recoveryclient.AuditSafe(r.RemoteAddr), Outcome: outcome})
	if err != nil && !errors.Is(err, recoveryclient.ErrReceiptUnrecorded) {
		s.backupError(w, r, err)
		return
	}
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

func (s *Server) postBackupDrill(w http.ResponseWriter, r *http.Request) {
	b := s.o.Backup
	if b == nil {
		s.backupError(w, r, errors.New("backup service is unavailable"))
		return
	}
	result, err := b.Drill(r.Context())
	details, outcome := "", "success"
	if err != nil {
		details, outcome = err.Error(), "failure"
	} else if !result.Passed {
		details, outcome = result.ErrorMessage, "failure"
	}
	_ = b.Store.RecordAudit(store.AuditEvent{Actor: "admin", Action: "backup.drill",
		Details: recoveryclient.AuditSafe(details), IP: recoveryclient.AuditSafe(r.RemoteAddr), Outcome: outcome})
	if err != nil {
		s.backupError(w, r, err)
		return
	}
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

func (s *Server) getBackupExport(w http.ResponseWriter, r *http.Request) {
	b := s.o.Backup
	if b == nil {
		http.Error(w, "backup unavailable", 503)
		return
	}
	raw, manifest, err := b.Export()
	if err != nil {
		// A node with no key to seal to is a precondition the operator can fix,
		// the same answer the JSON transport gives; anything else is this box.
		code := 500
		if errors.Is(err, recoveryclient.ErrNotPaired) || errors.Is(err, recoveryclient.ErrKeyPinMissing) || errors.Is(err, recoveryclient.ErrKeyMismatch) {
			code = 412
		}
		http.Error(w, backupMessage(err), code)
		return
	}
	if err := b.Store.RecordAudit(store.AuditEvent{Actor: "admin", Action: "backup.exported",
		Resource: manifest.CapsuleID, IP: recoveryclient.AuditSafe(r.RemoteAddr), Outcome: "success"}); err != nil {
		http.Error(w, "audit failed; capsule not exported", 503)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+backup.ServiceName+"."+recoveryclient.FilenameSafe(manifest.CapsuleID)+`.kycap"`)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(raw)
}

// backupView is backup.Status as the template needs it: minutes, because the schedule
// form is in minutes and html/template has no arithmetic and this package has no funcmap.
type backupView struct {
	backup.Status
	IntervalMinutes int64
}
