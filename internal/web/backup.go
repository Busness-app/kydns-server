package web

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/Busness-app/ky-primitives/recoveryclient"
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
	key, err := b.Pair(r.Context(), u, code)
	details := u + " allow_private=" + strconv.FormatBool(b.Cfg.BackupAllowPrivateRecovery)
	outcome := "success"
	if err != nil {
		outcome, details = "failure", details+" "+err.Error()
	}
	_ = b.Store.RecordAudit(store.AuditEvent{Actor: "admin", Action: "backup.paired",
		Resource: key.Public.ID(), Details: recoveryclient.AuditSafe(details),
		IP: recoveryclient.AuditSafe(r.RemoteAddr), Outcome: outcome})
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
		if errors.Is(err, recoveryclient.ErrNotPaired) || errors.Is(err, recoveryclient.ErrKeyPinMissing) {
			code = 412
		}
		http.Error(w, err.Error(), code)
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
