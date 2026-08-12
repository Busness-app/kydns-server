// Package upstream turns configured upstream strings into resolvers. The
// scheme in the string is the security policy: tls:// and https:// are
// authenticated and encrypted, udp:// and a bare host:port are not.
package upstream

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"
)

type Transport int

const (
	Plain Transport = iota
	DoT
	DoH
)

func (t Transport) String() string {
	switch t {
	case DoT:
		return "DoT"
	case DoH:
		return "DoH"
	default:
		return "plaintext"
	}
}

// Secure reports whether the transport authenticates and encrypts the channel.
// Only a secure transport may carry an AD bit through to a client.
func (t Transport) Secure() bool { return t == DoT || t == DoH }

// Spec is a parsed upstream. Addr is always what gets dialed; ServerName and
// URL only decide what the peer is asked to be.
type Spec struct {
	Raw        string
	Transport  Transport
	Addr       string
	ServerName string
	URL        string // DoH only

	// RootCAs overrides the system trust store. Production leaves it nil;
	// tests set it to trust a self-signed server certificate.
	RootCAs *x509.CertPool
}

func (s Spec) Secure() bool   { return s.Transport.Secure() }
func (s Spec) String() string { return s.Raw }

const bootstrapHint = "host must be an IP address — DNS cannot bootstrap DNS. " +
	"Use the provider's IP, and add #servername if its certificate needs a hostname"

// Parse turns one configured string into a Spec.
func Parse(raw string) (Spec, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return Spec{}, errors.New("upstream is empty")
	}
	if !strings.Contains(s, "://") {
		addr, err := hostPort(s, "53")
		if err != nil {
			return Spec{}, fmt.Errorf("upstream %q: %w", raw, err)
		}
		return Spec{Raw: raw, Transport: Plain, Addr: addr}, nil
	}

	u, err := url.Parse(s)
	if err != nil {
		return Spec{}, fmt.Errorf("upstream %q: %w", raw, err)
	}
	spec := Spec{Raw: raw, ServerName: u.Fragment}
	var defPort string
	switch u.Scheme {
	case "udp":
		spec.Transport, defPort = Plain, "53"
	case "tls":
		spec.Transport, defPort = DoT, "853"
	case "https":
		spec.Transport, defPort = DoH, "443"
	default:
		return Spec{}, fmt.Errorf(
			"upstream %q: unknown scheme %q, want udp://, tls://, or https://", raw, u.Scheme)
	}
	if spec.Addr, err = hostPort(u.Host, defPort); err != nil {
		return Spec{}, fmt.Errorf("upstream %q: %w", raw, err)
	}
	if spec.Transport == DoH {
		path := u.Path
		if path == "" {
			path = "/dns-query"
		}
		spec.URL = "https://" + dohAuthority(spec) + path
	}
	return spec, nil
}

// ParseAll parses a whole configured list, failing on the first bad entry so a
// typo never starts a half-configured server.
func ParseAll(raws []string) ([]Spec, error) {
	specs := make([]Spec, 0, len(raws))
	for _, r := range raws {
		s, err := Parse(r)
		if err != nil {
			return nil, err
		}
		specs = append(specs, s)
	}
	return specs, nil
}

// hostPort requires an IP address and returns it as "ip:port" with defPort
// filled in.
func hostPort(s, defPort string) (string, error) {
	host, port := s, defPort
	if h, p, err := net.SplitHostPort(s); err == nil {
		host, port = h, p
	}
	addr, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil {
		return "", errors.New(bootstrapHint)
	}
	if _, err := net.LookupPort("tcp", port); err != nil {
		return "", fmt.Errorf("bad port %q", port)
	}
	return net.JoinHostPort(addr.String(), port), nil
}

// dohAuthority is the authority for the request URL. The socket always goes to
// Spec.Addr; this only decides what the server is asked to be.
func dohAuthority(s Spec) string {
	host, port, err := net.SplitHostPort(s.Addr)
	if err != nil {
		return s.Addr
	}
	switch {
	case s.ServerName != "":
		host = s.ServerName
	case strings.Contains(host, ":"):
		host = "[" + host + "]"
	}
	if port == "443" {
		return host
	}
	return host + ":" + port
}
