package config

import (
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// LoadOptions supplies external inputs explicitly. Nil Environ applies no
// environment overrides. Flags must contain only explicitly set flag values,
// represented as flag.Value.String() would return them; empty flag values count.
type LoadOptions struct {
	Environ []string
	Flags   map[string]string
}

// Loaded retains the complete resulting raw map, including unknown file keys
// and DNS_ environment entries that do not belong to the 157-field Config.
type Loaded struct {
	Config Config            `json:"config"`
	Values map[string]string `json:"values"`
	// Explicit records user-supplied keys, including values equal to defaults.
	// Runtime compatibility migrations must not override an explicit false.
	Explicit map[string]bool `json:"explicit,omitempty"`
}

// ParseText reproduces the file parsing stage at 0x1324020. Duplicate keys use
// the last value. Only lines whose first trimmed byte is '#' are comments.
// Cut uses the first '='; quotes, escapes, sections and expansion have no role.
// Inline " #" removal is a later, shared pipeline stage, not performed here.
func ParseText(text string) map[string]string {
	values := make(map[string]string)
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		values[strings.ToLower(strings.TrimSpace(key))] = strings.TrimSpace(value)
	}
	return values
}

// CleanValue reproduces 0x13241a0: cut at the first literal space-plus-#,
// then TrimSpace. A bare '#' or tab-plus-# inside a value is preserved.
func CleanValue(value string) string {
	if i := strings.Index(value, " #"); i >= 0 {
		value = value[:i]
	}
	return strings.TrimSpace(value)
}

// Load reproduces the known stages of 0x1323be0: metadata defaults, file,
// environment, explicitly set flags, shared value cleanup, typed assignment.
// It does not invoke the original post-load callback list (runtime/service
// validation and side effects outside this package's recovered scope).
func Load(r io.Reader, options LoadOptions) (*Loaded, error) {
	values := DefaultValues()
	explicit := map[string]bool{}
	if r != nil {
		text, err := io.ReadAll(r)
		if err != nil {
			return nil, err
		}
		for key, value := range ParseText(string(text)) {
			values[key] = value
			explicit[key] = true
		}
	}
	for _, entry := range options.Environ {
		parts := SplitClean(entry, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key, value := parts[0], parts[1]
		if strings.HasPrefix(key, "DNS_") {
			if value != "" {
				values[strings.ToLower(key)] = value
				explicit[strings.ToLower(key)] = true
			}
		} else if _, registered := fieldIndices[key]; registered {
			// Raw key lookup occurs before ToLower in 0x1323df3..0x1323e12.
			// Consequently uppercase ordinary names are not accepted here.
			values[strings.ToLower(key)] = value
			explicit[strings.ToLower(key)] = true
		}
	}
	flagNames := make([]string, 0, len(options.Flags))
	for key := range options.Flags {
		flagNames = append(flagNames, key)
	}
	sort.Strings(flagNames) // flag.FlagSet.Visit traverses set flags by name.
	for _, key := range flagNames {
		values[strings.ToLower(key)] = options.Flags[key]
		explicit[strings.ToLower(key)] = true
	}
	for key, value := range values {
		values[key] = CleanValue(value)
	}
	return &Loaded{Config: FromValues(values), Values: values, Explicit: explicit}, nil
}

type FileOptions struct {
	LoadOptions
	// Opt-in equivalent of the missing-config creation stage. The default
	// keeps LoadFile read-only; this option is an added embedding API control.
	CreateIfMissing bool
}

// LoadFile uses the path exactly as supplied. Call NormalizeConfigPath
// explicitly if the original prefix behavior is desired.
func LoadFile(path string, options FileOptions) (*Loaded, error) {
	if options.CreateIfMissing {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			// The original ignores MkdirAll/Close errors and returns OpenFile
			// or subsequent ReadFile errors. The mode arguments are observed.
			_ = os.MkdirAll(filepath.Dir(path), 0755)
			f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
			if err != nil {
				return nil, err
			}
			_ = f.Close()
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Load(strings.NewReader(string(data)), options.LoadOptions)
}
