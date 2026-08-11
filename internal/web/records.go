package web

import (
	"net/http"
	"strconv"

	"github.com/yoshiofthewire/kydns-server/internal/store"
)

// recordTypes mirrors registry.ValidateRecordType. The dropdown offers exactly
// what v1 supports, so an unsupported type is not reachable by accident and
// the server-side check is a backstop rather than the only guard.
var recordTypes = []string{"A", "AAAA", "CNAME", "PTR"}

func (s *Server) recordsData(errMsg string) map[string]any {
	recs, err := s.o.Registry.Records()
	if err != nil && errMsg == "" {
		errMsg = err.Error()
	}
	views, _ := s.o.Registry.Views()
	return map[string]any{
		"Title": "Records", "Nav": "records",
		"Records": recs, "Views": views, "Types": recordTypes, "Error": errMsg,
	}
}

func (s *Server) getRecords(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "records.html", s.recordsData(""))
}

func (s *Server) renderRecordsError(w http.ResponseWriter, r *http.Request, msg string) {
	w.WriteHeader(http.StatusBadRequest)
	s.render(w, r, "records.html", s.recordsData(msg))
}

func (s *Server) postRecordNew(w http.ResponseWriter, r *http.Request) {
	rec := store.Record{
		Name:  r.PostFormValue("name"),
		Type:  r.PostFormValue("type"),
		Value: r.PostFormValue("value"),
		View:  r.PostFormValue("view"),
	}
	if _, err := s.o.Registry.PutRecord(rec); err != nil {
		s.renderRecordsError(w, r, err.Error())
		return
	}
	http.Redirect(w, r, "/records", http.StatusSeeOther)
}

func (s *Server) postRecordDelete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PostFormValue("id"), 10, 64)
	if err == nil {
		err = s.o.Registry.DeleteRecord(id)
	}
	if err != nil {
		s.renderRecordsError(w, r, err.Error())
		return
	}
	http.Redirect(w, r, "/records", http.StatusSeeOther)
}
