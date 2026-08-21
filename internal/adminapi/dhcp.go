package adminapi

import "net/http"

// WithDHCP attaches the built-in server's runner status. It is optional: a
// build with no runner reports not running, which is what such a node is.
func (a *API) WithDHCP(status func() (bool, error)) *API {
	a.dhcpStatus = status
	return a
}

// getDHCPStatus is the one thing GET /api/v1/leases cannot express: whether
// the listener is up, and why not. "Off" and "refused to start" both show an
// empty lease table, and only the second has a reason to act on.
func (a *API) getDHCPStatus(w http.ResponseWriter, _ *http.Request) {
	out := struct {
		Running bool   `json:"running"`
		Error   string `json:"error,omitempty"`
	}{}
	if a.dhcpStatus != nil {
		running, err := a.dhcpStatus()
		out.Running = running
		if err != nil {
			out.Error = err.Error()
		}
	}
	writeJSON(w, http.StatusOK, out)
}
