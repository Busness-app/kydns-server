package adminapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/Busness-app/ky-primitives/capsule"
	"github.com/Busness-app/kydns-server/internal/backup"
	"github.com/Busness-app/kydns-server/internal/config"
	"github.com/Busness-app/kydns-server/internal/store"
)

type BackupService struct {
	Config  *config.Config
	Store   *store.Store
	Client  *backup.Client
	Version string
}

func (a *API) requireBackup(w http.ResponseWriter) *BackupService {
	if a.backup == nil {
		writeErr(w, http.StatusServiceUnavailable, "backup_unavailable", "", "backup service is unavailable")
		return nil
	}
	return a.backup
}

func backupAudit(st *store.Store, action, resource, details, ip, outcome string) error {
	return st.RecordAudit(store.AuditEvent{Actor: "admin", Action: action,
		Resource: backup.AuditSafe(resource), Details: backup.AuditSafe(details),
		IP: backup.AuditSafe(ip), Outcome: outcome})
}

func backupStatusCode(err error) int {
	switch {
	case errors.Is(err, backup.ErrNotPaired), errors.Is(err, backup.ErrKeyPinMissing):
		return http.StatusPreconditionFailed
	case errors.Is(err, backup.ErrDepositInProgress):
		return http.StatusConflict
	case errors.Is(err, backup.ErrRemote):
		return http.StatusBadGateway
	default:
		return http.StatusInternalServerError
	}
}

func (a *API) backupStatus(w http.ResponseWriter, _ *http.Request) {
	s := a.requireBackup(w)
	if s == nil {
		return
	}
	status, err := backup.ReadStatus(s.Store)
	if err != nil {
		writeErr(w, 500, "backup_status", "", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, status)
}

func (a *API) backupPair(w http.ResponseWriter, r *http.Request) {
	s := a.requireBackup(w)
	if s == nil {
		return
	}
	var req struct {
		RecoveryURL string `json:"recovery_url"`
		PairingCode string `json:"pairing_code"`
	}
	if !decode(w, r, &req) {
		return
	}
	result, err := s.Client.Claim(r.Context(), req.RecoveryURL, req.PairingCode)
	if err == nil {
		err = backup.StorePairing(s.Store, s.Config.DataDir, req.RecoveryURL, result.Token, result.Key)
	}
	outcome := "success"
	if err != nil {
		outcome = "failure"
	}
	_ = backupAudit(s.Store, "backup.paired", result.Key.Public.ID(), req.RecoveryURL+" "+fmt.Sprint(err), r.RemoteAddr, outcome)
	if err != nil {
		writeErr(w, backupStatusCode(err), "backup_pair", "", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"paired": true, "recovery_key_id": result.Key.Public.ID()})
}

func (a *API) backupExport(w http.ResponseWriter, r *http.Request) {
	s := a.requireBackup(w)
	if s == nil {
		return
	}
	key, err := backup.LoadRecoveryKey(s.Store, s.Config.DataDir)
	var raw []byte
	var manifest capsule.Manifest
	if err == nil {
		raw, manifest, err = backup.Seal(s.Config, s.Store, s.Version, key)
	}
	if err != nil {
		_ = backupAudit(s.Store, "backup.export_failed", manifest.CapsuleID, err.Error(), r.RemoteAddr, "failure")
		writeErr(w, backupStatusCode(err), "backup_export", "", err.Error())
		return
	}
	if err := backupAudit(s.Store, "backup.exported", manifest.CapsuleID, "", r.RemoteAddr, "success"); err != nil {
		writeErr(w, 503, "audit_failed", "", "capsule was not exported because its audit record failed")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="kydns-backup.kycap"`)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(raw)
}

func (a *API) backupDeposit(w http.ResponseWriter, r *http.Request) {
	s := a.requireBackup(w)
	if s == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 16*time.Minute)
	defer cancel()
	receipt, manifest, err := backup.Deposit(ctx, s.Config, s.Store, s.Store, s.Client, s.Version)
	action, outcome, details := "backup.deposited", "success", receipt.Digest
	if err != nil && !errors.Is(err, backup.ErrReceiptUnrecorded) {
		action, outcome, details = "backup.deposit_failed", "failure", err.Error()
	}
	_ = backupAudit(s.Store, action, manifest.CapsuleID, details, r.RemoteAddr, outcome)
	if err != nil {
		writeErr(w, backupStatusCode(err), "backup_deposit", "", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, receipt)
}

func (a *API) backupDrill(w http.ResponseWriter, r *http.Request) {
	s := a.requireBackup(w)
	if s == nil {
		return
	}
	result, err := backup.Drill(s.Config, s.Store, s.Version)
	outcome := "success"
	if err != nil {
		outcome = "failure"
	}
	_ = backupAudit(s.Store, "backup.drill", "", fmt.Sprint(err), r.RemoteAddr, outcome)
	if err != nil {
		writeErr(w, backupStatusCode(err), "backup_drill", "", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}
