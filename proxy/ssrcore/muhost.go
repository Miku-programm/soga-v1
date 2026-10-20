package ssrcore

import (
	"crypto/md5"
	"encoding/hex"
	"errors"
	"regexp"
	"strconv"
	"strings"
)

var muMD5Placeholder = regexp.MustCompile(`%(\d+)m`)

// HostForUser reproduces the statically recovered GetSSRHost/GenUserMd5 rule.
// ID is the billing ID, not the optional protocol UID. Method/Obfs/Protocol
// describe the user's own panel record, not the single-port carrier record.
func HostForUser(u User, pattern, suffix string) (string, error) {
	if pattern == "" || suffix == "" {
		return "", errors.New("ssr: mu_regex and mu_suffix are required")
	}
	match := muMD5Placeholder.FindStringSubmatch(pattern)
	if len(match) != 2 {
		// The original implementation panics on a missing match; configuration
		// validation returns an error instead of crashing the reconstructed server.
		return "", errors.New("ssr: mu_regex requires a %<digits>m placeholder")
	}
	n, err := strconv.ParseUint(match[1], 10, 63)
	if err != nil {
		return "", errors.New("ssr: invalid mu_regex MD5 prefix length")
	}
	digest := md5.Sum([]byte(strconv.FormatInt(u.ID, 10) + u.Password + u.Method + u.Obfs + u.Protocol))
	result := strings.Replace(pattern, match[0], hex.EncodeToString(digest[:])[:min(n, 32)], 1)
	result = strings.Replace(result, "%id", strconv.FormatInt(u.ID, 10), 1)
	return strings.Replace(result, "%suffix", suffix, 1), nil
}
