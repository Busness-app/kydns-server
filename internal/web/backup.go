package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/Busness-app/kydns-server/internal/backup"
	"github.com/Busness-app/kydns-server/internal/store"
)

func (s *Server) backupError(w http.ResponseWriter, r *http.Request, err error) {
	w.WriteHeader(http.StatusBadRequest)
	s.render(w, r, "settings.html", s.settingsData(err.Error(), ""))
}

func (s *Server) postBackupPair(w http.ResponseWriter, r *http.Request) {
	b := s.o.Backup
	if b == nil {
		s.backupError(w, r, errors.New("backup service is unavailable"))
		return
	}
	u, code := r.PostFormValue("recovery_url"), r.PostFormValue("pairing_code")
	result, err := b.Client.Claim(r.Context(), u, code)
	if err == nil {
		err = backup.StorePairing(b.Store, b.Config.DataDir, u, result.Token, result.Key)
	}
	outcome := "success"
	if err != nil {
		outcome = "failure"
	}
	_ = b.Store.RecordAudit(store.AuditEvent{Actor: "admin", Action: "backup.paired", Resource: result.Key.Public.ID(), Details: backup.AuditSafe(u + " " + fmt.Sprint(err)), IP: backup.AuditSafe(r.RemoteAddr), Outcome: outcome})
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
	receipt, manifest, err := backup.Deposit(ctx, b.Config, b.Store, b.Store, b.Client, b.Version)
	outcome, action, details := "success", "backup.deposited", receipt.Digest
	if err != nil && !errors.Is(err, backup.ErrReceiptUnrecorded) {
		outcome, action, details = "failure", "backup.deposit_failed", err.Error()
	}
	_ = b.Store.RecordAudit(store.AuditEvent{Actor: "admin", Action: action, Resource: manifest.CapsuleID, Details: backup.AuditSafe(details), IP: backup.AuditSafe(r.RemoteAddr), Outcome: outcome})
	if err != nil {
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
	_, err := backup.Drill(b.Config, b.Store, b.Version)
	outcome := "success"
	if err != nil {
		outcome = "failure"
	}
	_ = b.Store.RecordAudit(store.AuditEvent{Actor: "admin", Action: "backup.drill", Details: backup.AuditSafe(fmt.Sprint(err)), IP: backup.AuditSafe(r.RemoteAddr), Outcome: outcome})
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
	key, err := backup.LoadRecoveryKey(b.Store, b.Config.DataDir)
	if err != nil {
		http.Error(w, err.Error(), 412)
		return
	}
	raw, manifest, err := backup.Seal(b.Config, b.Store, b.Version, key)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if err := b.Store.RecordAudit(store.AuditEvent{Actor: "admin", Action: "backup.exported", Resource: manifest.CapsuleID, IP: backup.AuditSafe(r.RemoteAddr), Outcome: "success"}); err != nil {
		http.Error(w, "audit failed; capsule not exported", 503)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="kydns-backup.kycap"`)
	_, _ = w.Write(raw)
}
