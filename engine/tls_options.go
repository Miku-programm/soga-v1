package engine

import (
	"crypto/tls"
	"fmt"
	"strconv"
	"strings"
)

// The documented list is colon-separated and permits either a Go cipher name
// or a hexadecimal IANA ID. A comma is also accepted for existing configs.
func tlsCipherNames(raw string) ([]string, error) {
	var names []string
	known := append(tls.CipherSuites(), tls.InsecureCipherSuites()...)
	seen := map[string]bool{}
	for _, token := range strings.FieldsFunc(raw, func(r rune) bool { return r == ':' || r == ',' }) {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}
		name := ""
		for _, suite := range known {
			if token == suite.Name {
				name = suite.Name
				break
			}
		}
		if name == "" && (strings.HasPrefix(token, "0x") || strings.HasPrefix(token, "0X")) {
			id, err := strconv.ParseUint(token[2:], 16, 16)
			if err == nil {
				for _, suite := range known {
					if suite.ID == uint16(id) {
						name = suite.Name
						break
					}
				}
			}
		}
		if name == "" {
			return nil, fmt.Errorf("unknown tls_cipher_suites entry %q", token)
		}
		if !seen[name] {
			names = append(names, name)
			seen[name] = true
		}
	}
	return names, nil
}
