# Reconstructed configuration package

This package is independently written from soga-v2.17.0 instructions, Go reflection metadata, and statically decoded strings. It is not the original source. It has no unassigned hooks and does not require the analyzed executable.

The schema contains all 157 recovered `conf` fields and 111 explicit `default` tags. Its exported names and JSON tags are added interfaces. The original 64-bit Go `int` fields use `int64`; the original 28 separate structures are flattened into `Config`.

`Load(reader, options)` follows the recovered value pipeline:

1. Register every metadata default; fields without a default tag receive empty text.
2. Read file text, trim lines, skip empty lines and lines starting with `#`, and split at the first `=`. Trim both sides and lowercase the key. Later occurrences overwrite earlier values, including empty values. Unknown keys remain in `Loaded.Values`.
3. Apply explicitly supplied environment entries through `SplitClean(entry, "=", 2)`. Empty pieces are removed. Ordinary keys must match the registered lowercase spelling before normalization. Uppercase `DNS_` names have a separate acceptance branch. Empty environment values cannot clear earlier values.
4. Apply only explicitly set flags supplied in `LoadOptions.Flags`, in name order. Empty flag values **do** override earlier values.
5. For every value, remove text from the first literal ` #` onward, then trim whitespace. Quotes and escapes have no special meaning; a bare `#` or a tab followed by `#` is preserved.
6. Assign the resulting text to the typed fields.

The original post-load callback list is outside this package. Passing a nil reader is a new embedding convenience that skips file input. The package never reads process environment variables implicitly. `LoadFile` is read-only unless `CreateIfMissing` is explicitly selected; the opt-in existence check is limited to `os.IsNotExist` and does not claim the original helper's behavior for other filesystem errors.

`FromValues` and `Config.SetRaw` expose the assignment boundary without trimming, key normalization, default merging, or comment removal. `AssignValue` reproduces the full reflection kind dispatch: exact text `true` for booleans; decimal signed integers and float64 parsing, with parse errors replaced by zero; direct strings; and trimmed, empty-filtered string slices. It preserves reflection's own non-settable, invalid-value, narrow-type truncation, and type-assignment behavior. It rejects the exact `time.Duration` type and unsupported kinds with the statically decoded panic text.

`NormalizeServerType` lowercases without trimming and recognizes the recovered aliases `shadowsocks`, `shadowsocksr`, and `vmess`. `NormalizeConfigPath` and `NormalizeDNSPath` only preserve strings starting with `/`, or prepend `/etc/soga/`; they do not clean paths. `EffectiveWebAPIKey` selects `webapi_key` before `webapi_mukey`. `UsesLegacyWebAPIKey` and the decoded `LegacyWebAPIKeyWarning` expose the original warning condition without introducing global logging.

The use of `strings.ToLower`, `TrimSpace`, and `SplitN` is supported by raw rune-mapping control flow, explicit `unicode.ToLower` / `unicode.IsSpace` function values, the ASCII whitespace table, and `internal/stringslite.Index` calls. Unicode table data follows the build toolchain version; the original Unicode table version has not been identified. Numeric error type/message identity is intentionally outside the final-value equivalence boundary.

Evidence is recorded in `outputs/soga-analysis/reconstruction-evidence/config/evidence.json` and the adjacent assembly exports. The nine configuration test groups cover schema/default counts, malformed and overflowing values, Unicode and invalid UTF-8, empty slices, reflection panic boundaries, file grammar, precedence, environment casing, explicit empty flags, path behavior, and read-only versus opt-in file creation.
