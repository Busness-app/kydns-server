package policy

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

// The three list formats KyDNS ingests.
const (
	FormatDomains = "domains"
	FormatHosts   = "hosts"
	FormatAdblock = "adblock"
)

// maxEntries bounds a parsed list. Downloaded lists are untrusted input, and
// the fetcher's byte ceiling alone does not bound the map this builds.
const maxEntries = 1 << 21

// maxLineBytes bounds one line, so a single unterminated line cannot be read
// into memory without limit.
const maxLineBytes = 4096

// localNames are the hosts-file entries every list carries and no resolver
// should ever blackhole.
var localNames = map[string]bool{
	"localhost": true, "localhost.localdomain": true, "local": true,
	"broadcasthost": true, "ip6-localhost": true, "ip6-loopback": true,
	"ip6-localnet": true, "ip6-mcastprefix": true,
	"ip6-allnodes": true, "ip6-allrouters": true, "ip6-allhosts": true,
}

func ValidFormat(f string) bool {
	return f == FormatDomains || f == FormatHosts || f == FormatAdblock
}

// ParseResult is one parsed list. Skipped counts every line that produced no
// domain, so the UI can show that a list loaded but half of it was unusable.
type ParseResult struct {
	Domains []string
	Skipped int
}

// Parse reads a list body. It never returns a partial result: a caller that
// gets an error keeps its previous snapshot.
func Parse(r io.Reader, format string) (ParseResult, error) {
	return parseLimit(r, format, maxEntries)
}

// parseLimit is Parse with an injectable ceiling, so the ceiling can be tested
// without building a two-million-line fixture.
func parseLimit(r io.Reader, format string, max int) (ParseResult, error) {
	if !ValidFormat(format) {
		return ParseResult{}, fmt.Errorf("unknown list format %q", format)
	}
	var res ParseResult
	seen := map[string]struct{}{}
	br := bufio.NewReaderSize(r, maxLineBytes)
	for {
		raw, err := br.ReadSlice('\n')
		if err == bufio.ErrBufferFull {
			// The line exceeds the ceiling: count it once, then discard the
			// rest of it without growing any buffer.
			res.Skipped++
			for err == bufio.ErrBufferFull {
				_, err = br.ReadSlice('\n')
			}
			if err != nil && err != io.EOF {
				return ParseResult{}, err
			}
			if err == io.EOF {
				break
			}
			continue
		}
		if err != nil && err != io.EOF {
			return ParseResult{}, err
		}
		done := err == io.EOF
		if line := strings.TrimSpace(string(raw)); line != "" &&
			!strings.HasPrefix(line, "#") && !strings.HasPrefix(line, "!") {
			names, ok := lineDomains(line, format)
			if !ok || len(names) == 0 {
				res.Skipped++
			} else {
				added := 0
				for _, name := range names {
					n, nerr := Normalize(name)
					if nerr != nil || localNames[n] {
						continue
					}
					added++
					if _, dup := seen[n]; dup {
						continue
					}
					seen[n] = struct{}{}
					if len(seen) > max {
						return ParseResult{}, errors.New("list exceeds the entry ceiling")
					}
				}
				if added == 0 {
					res.Skipped++
				}
			}
		}
		if done {
			break
		}
	}
	res.Domains = make([]string, 0, len(seen))
	for n := range seen {
		res.Domains = append(res.Domains, n)
	}
	sort.Strings(res.Domains)
	return res, nil
}

// lineDomains extracts the candidate names from one line. It returns false for
// a line the format cannot represent at all.
func lineDomains(line, format string) ([]string, bool) {
	switch format {
	case FormatDomains:
		if strings.ContainsAny(line, " \t/") {
			return nil, false
		}
		return []string{line}, true

	case FormatHosts:
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return nil, false
		}
		// The first field is the sink address; everything after it is a name.
		return fields[1:], true

	case FormatAdblock:
		// Only the plain domain-anchored form is supported. Exception rules,
		// modifiers, cosmetic filters and path rules are not domain filtering,
		// so they are skipped rather than half-honored.
		if !strings.HasPrefix(line, "||") || strings.ContainsAny(line, "$/*#@") {
			return nil, false
		}
		rule := strings.TrimSuffix(strings.TrimPrefix(line, "||"), "^")
		if rule == "" || strings.Contains(rule, "^") {
			return nil, false
		}
		return []string{rule}, true
	}
	return nil, false
}
