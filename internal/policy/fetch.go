package policy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// MaxListBytes bounds one download. The largest maintained hosts file is a few
// megabytes; this leaves room without letting a hostile source exhaust memory.
const MaxListBytes int64 = 32 << 20

// maxRedirects bounds a redirect chain.
const maxRedirects = 5

// userAgent is fixed and says nothing about this installation or its users.
const userAgent = "kydns"

// FetchResult is one download. NotModified means the server answered 304 and
// the caller should keep its current snapshot.
type FetchResult struct {
	Body         []byte
	ETag         string
	LastModified string
	NotModified  bool
}

// Fetcher downloads list bodies. Client is exported so a test can swap its
// transport; production code never touches it.
type Fetcher struct {
	Client   *http.Client
	MaxBytes int64
}

func NewFetcher(timeout time.Duration) *Fetcher {
	return &Fetcher{
		MaxBytes: MaxListBytes,
		Client: &http.Client{
			Timeout: timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= maxRedirects {
					return fmt.Errorf("stopped after %d redirects", maxRedirects)
				}
				// A redirect off HTTPS would silently drop verification.
				if req.URL.Scheme != "https" {
					return fmt.Errorf("redirect to a non-https URL (%s)", req.URL.Scheme)
				}
				return nil
			},
		},
	}
}

// Fetch downloads rawURL over verified HTTPS. It sends the cache validators it
// is given and nothing else: no query names, no client addresses, no cookies.
func (f *Fetcher) Fetch(ctx context.Context, rawURL, etag, lastModified string) (FetchResult, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return FetchResult{}, err
	}
	if u.Scheme != "https" {
		return FetchResult{}, errors.New("a list URL must be https")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return FetchResult{}, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "text/plain")
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	if lastModified != "" {
		req.Header.Set("If-Modified-Since", lastModified)
	}

	resp, err := f.Client.Do(req)
	if err != nil {
		// *url.Error embeds the full URL, including any query-string secret;
		// unwrap to the underlying cause before it reaches a log or the UI.
		var ue *url.Error
		if errors.As(err, &ue) {
			return FetchResult{}, fmt.Errorf("download failed: %w", ue.Err)
		}
		return FetchResult{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		return FetchResult{NotModified: true}, nil
	}
	if resp.StatusCode != http.StatusOK {
		return FetchResult{}, fmt.Errorf("status %s", resp.Status)
	}

	// Read one byte past the ceiling so an oversized body is an error rather
	// than a silently truncated list.
	body, err := io.ReadAll(io.LimitReader(resp.Body, f.MaxBytes+1))
	if err != nil {
		return FetchResult{}, err
	}
	if int64(len(body)) > f.MaxBytes {
		return FetchResult{}, fmt.Errorf("list exceeds %d bytes", f.MaxBytes)
	}
	return FetchResult{
		Body:         body,
		ETag:         resp.Header.Get("ETag"),
		LastModified: resp.Header.Get("Last-Modified"),
	}, nil
}
