// Package rulelist reconstructs the observed local and remote rule-list loading
// paths. Runtime rule matching is implemented separately in package policy.
package rulelist

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
)

// Store publishes a completed local list atomically. The zero value is usable.
// Original globals: block 0x5095a90; white 0x5095ad8.
type Store struct {
	local atomic.Pointer[[]string]
}

// Snapshot returns an independent, non-nil slice. Copying is an API ownership
// choice of this reconstruction; the binary returns the stored slice directly.
func (s *Store) Snapshot() []string {
	p := s.local.Load()
	if p == nil {
		return []string{}
	}
	return append([]string{}, (*p)...)
}

// ReadLocal reconstructs the parsing loop at 0x131a4a0 (block list) and
// 0x133e760 (white list). Pass nil forbiddenPorts for a white list.
//
// The binary ignores bufio.Reader.ReadLine's isPrefix flag. We preserve that:
// a line longer than the 4096-byte reader buffer is treated as several entries.
// Any terminal read error ends parsing; accumulated entries and forbidden-port
// rules are retained. Returning that error is an added diagnostic API.
func ReadLocal(r io.Reader, forbiddenPorts []string) ([]string, error) {
	// Hide a caller's *bufio.Reader so NewReaderSize cannot reuse a larger
	// buffer: the original always allocates 4096 bytes around an *os.File.
	reader := bufio.NewReaderSize(struct{ io.Reader }{r}, 4096)
	rules := make([]string, 0)
	var terminal error
	for {
		line, _, err := reader.ReadLine()
		if err != nil {
			if !errors.Is(err, io.EOF) {
				terminal = err
			}
			break
		}
		text := strings.TrimSpace(string(line))
		if text == "" || text[0] == '#' {
			continue
		}
		// The original splits at every '#', then takes and trims element zero.
		// A Cut at the first delimiter has the same retained-prefix result.
		text, _, _ = strings.Cut(text, "#")
		rules = append(rules, strings.TrimSpace(text))
	}
	for _, port := range forbiddenPorts {
		// Literal at 0x20971c8; no validation or deduplication at this site.
		rules = append(rules, "port:"+port)
	}
	return rules, terminal
}

// LoadLocal updates the snapshot only when the local file opens successfully.
// A nonempty remoteURL suppresses local loading, including forbidden-port
// insertion, as in the binary. File-open failure retains the previous snapshot.
// Unlike the original void methods, this API reports whether a publish occurred
// and exposes I/O errors to the reconstruction's caller.
func (s *Store) LoadLocal(path, remoteURL string, forbiddenPorts []string) (bool, error) {
	if remoteURL != "" {
		return false, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	rules, readErr := ReadLocal(f, forbiddenPorts)
	s.local.Store(&rules)
	return true, readErr
}

// ParseRemote reconstructs the successful ReadAll -> SplitClean("\n", -1)
// path at 0x131a9a0. Unlike the local path, it keeps '#' comments verbatim
// after trimming and does not append forbidden_ports.
func ParseRemote(body string) []string {
	rules := make([]string, 0)
	for _, line := range strings.Split(strings.TrimSpace(body), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			rules = append(rules, line)
		}
	}
	return rules
}

// HTTPDoer allows a real HTTP client or a local test transport. It is an API
// adapter, not an unresolved decoder or business-logic Hook.
type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// Get returns the local snapshot when remoteURL is empty. Otherwise it fetches
// and parses the response body without checking the status code, preserving the
// observed getter behavior. Context and transport selection are explicit API
// adapters; the original shared client's timeout/proxy policy is not recovered.
// A remote fetch does not change the stored local snapshot.
func (s *Store) Get(ctx context.Context, remoteURL string, client HTTPDoer) ([]string, error) {
	if remoteURL == "" {
		return s.Snapshot(), nil
	}
	if client == nil {
		client = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, remoteURL, nil)
	if err != nil {
		return nil, err
	}
	response, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	return ParseRemote(string(body)), nil
}
