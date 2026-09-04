package backup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"

	"github.com/Busness-app/ky-primitives/recoverykey"
)

type Client struct{ http *http.Client }

func NewClient() *Client {
	d := &net.Dialer{Timeout: 10 * time.Second}
	t := &http.Transport{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
		if err != nil {
			return nil, err
		}
		for _, ip := range ips {
			if publicIP(ip) {
				return d.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			}
		}
		return nil, errors.New("recovery host resolves only to private or reserved addresses")
	}}
	h := &http.Client{Timeout: 30 * time.Second, Transport: t}
	h.CheckRedirect = func(*http.Request, []*http.Request) error { return errors.New("redirects are refused") }
	return &Client{http: h}
}

var blockedNetworks = mustNetworks("100.64.0.0/10", "192.0.0.0/24", "198.18.0.0/15", "240.0.0.0/4", "64:ff9b::/96", "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")

func mustNetworks(raw ...string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(raw))
	for _, s := range raw {
		_, n, _ := net.ParseCIDR(s)
		out = append(out, n)
	}
	return out
}
func publicIP(ip net.IP) bool {
	if ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
		return false
	}
	for _, n := range blockedNetworks {
		if n.Contains(ip) {
			return false
		}
	}
	return true
}

func endpoint(server, path string) (string, error) {
	u, err := url.Parse(strings.TrimRight(server, "/"))
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return "", errors.New("recovery URL must be a plain HTTPS origin")
	}
	if ip := net.ParseIP(u.Hostname()); ip != nil && !publicIP(ip) {
		return "", errors.New("recovery URL cannot target a private or reserved address")
	}
	u.Path = strings.TrimRight(u.Path, "/") + path
	return u.String(), nil
}

type PairingResult struct {
	Token string
	Key   RecoveryKey
}

func (c *Client) Claim(ctx context.Context, server, code string) (PairingResult, error) {
	code = strings.TrimSpace(code)
	if len(code) != 6 || strings.IndexFunc(code, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
		return PairingResult{}, errors.New("pairing code must be exactly six digits")
	}
	u, err := endpoint(server, "/api/pairing/claim")
	if err != nil {
		return PairingResult{}, err
	}
	body, _ := json.Marshal(map[string]string{"pairing_code": code, "service_name": serviceName, "app_name": serviceName})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return PairingResult{}, fmt.Errorf("%w: %v", ErrRemote, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return PairingResult{}, fmt.Errorf("%w: claim rejected (%d): %s", ErrRemote, resp.StatusCode, remote(resp.Body))
	}
	var out struct {
		APIToken          string `json:"api_token"`
		RecoveryPublicKey string `json:"recovery_public_key"`
		Threshold         int    `json:"threshold"`
		TotalShares       int    `json:"total_shares"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&out); err != nil {
		return PairingResult{}, err
	}
	raw, err := base64.StdEncoding.DecodeString(out.RecoveryPublicKey)
	if err != nil {
		return PairingResult{}, err
	}
	pub, err := recoverykey.ParsePublicKey(raw)
	if err != nil {
		return PairingResult{}, err
	}
	if out.APIToken == "" || out.Threshold < 2 || out.TotalShares < out.Threshold || out.TotalShares > 255 {
		return PairingResult{}, errors.New("invalid pairing response")
	}
	return PairingResult{Token: out.APIToken, Key: RecoveryKey{Public: pub, Threshold: out.Threshold, TotalShares: out.TotalShares}}, nil
}

func (c *Client) Deposit(ctx context.Context, server, token string, raw []byte) (Receipt, error) {
	u, err := endpoint(server, "/api/backup/deposit")
	if err != nil {
		return Receipt{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/octet-stream")
	h := *c.http
	h.Timeout = 0
	resp, err := h.Do(req)
	if err != nil {
		return Receipt{}, fmt.Errorf("%w: %v", ErrRemote, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return Receipt{}, fmt.Errorf("%w: deposit rejected (%d): %s", ErrRemote, resp.StatusCode, remote(resp.Body))
	}
	var r Receipt
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&r); err != nil {
		return r, fmt.Errorf("%w: %v", ErrRemote, err)
	}
	sum := sha256.Sum256(raw)
	digest := hex.EncodeToString(sum[:])
	if r.CapsuleID == "" || r.Digest != digest || r.SizeBytes != int64(len(raw)) {
		return Receipt{}, fmt.Errorf("%w: receipt does not match deposited capsule", ErrRemote)
	}
	return r, nil
}

func remote(r io.Reader) string {
	b, _ := io.ReadAll(io.LimitReader(r, 4096))
	return AuditSafe(string(b))
}
func AuditSafe(s string) string {
	var b strings.Builder
	for _, r := range s {
		if b.Len() >= 200 {
			b.WriteString("...")
			break
		}
		if r == '\n' || r == '\t' {
			b.WriteByte(' ')
		} else if unicode.IsPrint(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}
