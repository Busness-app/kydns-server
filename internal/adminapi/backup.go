package adminapi

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

func (a *API) requireBackup(w http.ResponseWriter) *backup.Service {
	if a.backup == nil {
		writeErr(w, http.StatusServiceUnavailable, "backup_unavailable", "", "backup service is unavailable")
		return nil
	}
	return a.backup
}

func backupAudit(st *store.Store, action, resource, details, ip, outcome string) error {
	return st.RecordAudit(store.AuditEvent{Actor: "admin", Action: action,
		Resource: recoveryclient.AuditSafe(resource), Details: recoveryclient.AuditSafe(details),
		IP: recoveryclient.AuditSafe(ip), Outcome: outcome})
}

// backupStatusCode maps a library error onto a status and the sentence that says
// what to do about it. Anything unrecognised is this server's fault, not the
// caller's, so it is a 500.
func backupStatusCode(err error) (int, string) {
	switch {
	case errors.Is(err, recoveryclient.ErrKeyPinMissing):
		return http.StatusPreconditionFailed, "paired but the recovery public key is missing or does not match the pin; restore recovery.pub or re-pair"
	case errors.Is(err, recoveryclient.ErrNotPaired):
		return http.StatusPreconditionFailed, "no recovery key: pair with KyRecovery or pin the suite key first"
	case errors.Is(err, recoveryclient.ErrNoDestination):
		return http.StatusPreconditionFailed, "nowhere to put a capsule: pair with KyRecovery or set KYDNS_BACKUP_DIR"
	// A second pin naming a different key is refused by the library with a wrapped
	// fs.ErrExist, and a swapped recovery.pub with ErrKeyMismatch. Both are the same
	// answer to the caller: this node is already committed to another key.
	case errors.Is(err, recoveryclient.ErrKeyMismatch), errors.Is(err, fs.ErrExist):
		return http.StatusConflict, "already pinned to a different recovery key"
	case errors.Is(err, recoveryclient.ErrInProgress):
		return http.StatusConflict, "a backup is already in progress"
	case errors.Is(err, recoveryclient.ErrBadInterval):
		return http.StatusBadRequest, err.Error()
	case errors.Is(err, recoveryclient.ErrRemote):
		return http.StatusBadGateway, recoveryclient.AuditSafe(err.Error())
	default:
		return http.StatusInternalServerError, recoveryclient.AuditSafe(err.Error())
	}
}

func (a *API) backupFail(w http.ResponseWriter, code string, err error) {
	status, msg := backupStatusCode(err)
	writeErr(w, status, code, "", msg)
}

// outcomeOf is the audit outcome word for an error.
func outcomeOf(err error) string {
	if err != nil {
		return "failure"
	}
	return "success"
}

func (a *API) backupStatus(w http.ResponseWriter, _ *http.Request) {
	s := a.requireBackup(w)
	if s == nil {
		return
	}
	status, err := s.Status()
	if err != nil {
		a.backupFail(w, "backup_status", err)
		return
	}
	writeJSON(w, http.StatusOK, status)
}

// pairURLError is the library's rule for where a capsule may be sent, with this
// product's switch named. The library says "the private-destination option"
// without knowing what KyDNS calls it, and an operator whose KyRecovery is on
// their own LAN has nowhere to go without the variable's name. The clause is
// added exactly when flipping the opt-in would change the answer, so a bad
// scheme or a stray query string is not answered with an irrelevant switch.
func pairURLError(raw string, allowPrivate bool) error {
	err := recoveryclient.ValidateURL(raw, allowPrivate)
	if err == nil || allowPrivate {
		return err
	}
	if lenient := recoveryclient.ValidateURL(raw, true); lenient == nil || lenient.Error() != err.Error() {
		return fmt.Errorf("%w; KYDNS_BACKUP_ALLOW_PRIVATE_RECOVERY admits a KyRecovery on your own network, never a loopback or link-local one", err)
	}
	return err
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
	// Checked before the claim, so a URL this node would never deposit to is
	// refused without presenting the pairing code to it.
	if err := pairURLError(req.RecoveryURL, s.Cfg.BackupAllowPrivateRecovery); err != nil {
		writeErr(w, http.StatusBadRequest, "backup_pair", "recovery_url", err.Error())
		return
	}
	key, err := s.Pair(r.Context(), req.RecoveryURL, req.PairingCode)
	details := req.RecoveryURL + " allow_private=" + strconv.FormatBool(s.Cfg.BackupAllowPrivateRecovery)
	if err != nil {
		details += " " + err.Error()
	}
	_ = backupAudit(s.Store, "backup.paired", key.Public.ID(), details, r.RemoteAddr, outcomeOf(err))
	if err != nil {
		a.backupFail(w, "backup_pair", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"paired": true, "recovery_key_id": key.Public.ID()})
}

func (a *API) backupPinKey(w http.ResponseWriter, r *http.Request) {
	s := a.requireBackup(w)
	if s == nil {
		return
	}
	var req struct {
		PublicKey   string `json:"public_key"`
		Threshold   int    `json:"threshold"`
		TotalShares int    `json:"total_shares"`
	}
	if !decode(w, r, &req) {
		return
	}
	key, err := s.PinKey(req.PublicKey, req.Threshold, req.TotalShares)
	details := strconv.Itoa(req.Threshold) + "-of-" + strconv.Itoa(req.TotalShares)
	if err != nil {
		details += " " + err.Error()
	}
	_ = backupAudit(s.Store, "backup.key_pinned", key.Public.ID(), details, r.RemoteAddr, outcomeOf(err))
	if err != nil {
		a.backupFail(w, "backup_pin_key", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"recovery_key_id": key.Public.ID(),
		"threshold": key.Threshold, "total_shares": key.TotalShares})
}

func (a *API) backupUnpair(w http.ResponseWriter, r *http.Request) {
	s := a.requireBackup(w)
	if s == nil {
		return
	}
	err := s.Unpair()
	_ = backupAudit(s.Store, "backup.unpaired", "", "url and sealed token rows removed; key pin kept", r.RemoteAddr, outcomeOf(err))
	if err != nil {
		a.backupFail(w, "backup_unpair", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"unpaired": true,
		"note": "Rows removed. The credential is dead only when the KyRecovery admin revokes it."})
}

func (a *API) backupSchedule(w http.ResponseWriter, r *http.Request) {
	s := a.requireBackup(w)
	if s == nil {
		return
	}
	var req struct {
		IntervalSec int64 `json:"interval_sec"`
	}
	if !decode(w, r, &req) {
		return
	}
	got, err := s.SetSchedule(req.IntervalSec)
	// The stored value read back, not the request: the audit row and the response
	// say what the scheduler will actually do.
	details := strconv.FormatInt(int64(got/time.Second), 10)
	if err != nil {
		details = strconv.FormatInt(req.IntervalSec, 10) + " " + err.Error()
	}
	_ = backupAudit(s.Store, "backup.schedule", "", details, r.RemoteAddr, outcomeOf(err))
	if err != nil {
		a.backupFail(w, "backup_schedule", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"interval_sec": int64(got / time.Second)})
}

// backupRun is POST /api/v1/backup/deposit: one seal delivered everywhere this
// node is configured to send it. The name is the CLI's and stays.
func (a *API) backupRun(w http.ResponseWriter, r *http.Request) {
	s := a.requireBackup(w)
	if s == nil {
		return
	}
	// An upload already started outlives the client hanging up on it.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 16*time.Minute)
	defer cancel()
	res, err := s.Run(ctx)
	action, outcome, details := recoveryclient.Outcome(res, err)
	b, _ := json.Marshal(details)
	// Stored whole: every value in the map is already bounded by the library, and
	// truncating the JSON would leave an unparseable row.
	_ = s.Store.RecordAudit(store.AuditEvent{Actor: "admin", Action: action,
		Resource: recoveryclient.AuditSafe(res.Manifest.CapsuleID), Details: string(b),
		IP: recoveryclient.AuditSafe(r.RemoteAddr), Outcome: outcome})
	// A capsule KyRecovery holds is a success even when the receipt went unwritten.
	if err != nil && !errors.Is(err, recoveryclient.ErrReceiptUnrecorded) {
		a.backupFail(w, "backup_run", err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (a *API) backupExport(w http.ResponseWriter, r *http.Request) {
	s := a.requireBackup(w)
	if s == nil {
		return
	}
	raw, m, err := s.Export()
	if err != nil {
		_ = backupAudit(s.Store, "backup.export_failed", m.CapsuleID, err.Error(), r.RemoteAddr, "failure")
		a.backupFail(w, "backup_export", err)
		return
	}
	// The capsule is the whole instance. A download nobody can account for later
	// is worse than a download that failed, so the record comes first.
	if err := backupAudit(s.Store, "backup.exported", m.CapsuleID, "", r.RemoteAddr, "success"); err != nil {
		writeErr(w, http.StatusServiceUnavailable, "audit_failed", "", "capsule was not exported because its audit record failed")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+backup.ServiceName+"."+recoveryclient.FilenameSafe(m.CapsuleID)+`.kycap"`)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(raw)
}

func (a *API) backupDrill(w http.ResponseWriter, r *http.Request) {
	s := a.requireBackup(w)
	if s == nil {
		return
	}
	result, err := s.Drill(r.Context())
	// A drill that ran and failed its checks is a failed drill, not a successful call.
	details, outcome := "", "success"
	if err != nil {
		details, outcome = err.Error(), "failure"
	} else if !result.Passed {
		details, outcome = result.ErrorMessage, "failure"
	}
	_ = backupAudit(s.Store, "backup.drill", "", details, r.RemoteAddr, outcome)
	if err != nil {
		a.backupFail(w, "backup_drill", err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}
