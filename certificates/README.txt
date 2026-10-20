Certificate compatibility implementation

This package is newly written Go code, not the original soga source.

API:
  Resolve(ctx, Options) (Paths, error)
  Options fields: CertFile, KeyFile, Domain, Mode, KeyLength, DNSProvider,
  Variables map[string]string, StateDir, ACMEExecutable.
  Paths fields: CertFile, KeyFile.

Custom files take precedence and must be a valid, matching certificate/key pair.
When Domain is supplied, the certificate must also cover it.

self:
  Generates RSA-2048 by default, or the requested supported RSA/ECDSA key.
  Certificate validity is one year; existing files are reused while more than
  one day remains. This validity policy is a reconstruction choice.
  Supports DNS names and IP SANs. Managed keys are written with mode 0600.
  Self-signed certificates require explicit trust configuration on the client.

http / dns:
  Uses official acmesh-official/acme.sh 3.1.6, published 2026-09-20, embedded
  verbatim with its GPL-3.0 license, provider scripts, per-file hashes and
  archive provenance under bundled/. It is separate third-party source, not
  recovered soga code. A compatible ACMEExecutable can be specified instead.
  Upstream: https://github.com/acmesh-official/acme.sh/tree/3.1.6
  CLI usage: https://github.com/acmesh-official/acme.sh#readme
  DNS guide: https://github.com/acmesh-official/acme.sh/wiki/dnsapi

  StateDir is required. It contains the extracted client, ACME account state
  and managed certificates. Upstream disallows spaces in its --home path,
  so the HTTP/DNS modes reject whitespace in StateDir.
  Requires Unix sh, openssl and curl/wget; HTTP standalone mode additionally
  requires the upstream client's standalone dependencies (socat) and port 80.
  The implementation explicitly selects Let's Encrypt; this is a new
  implementation choice, not a claim about the original binary's CA.

  DNSProvider must name an actual dns_* script in the pinned bundle.
  SupportedDNSProviders returns that inventory. The documented config entries
  DNS_CF_Email / DNS_CF_Key become CF_Email / CF_Key environment entries.
  The configuration loader lowercases keys, so names are matched
  case-insensitively against the selected provider script: dns_cf_key in
  soga.conf also becomes CF_Key. Registered dns_* settings are not passed.
  Credentials are passed literally, with restricted environment variable names.
  No configuration text, command line or reload hook is evaluated by this Go
  module. The upstream DNS provider scripts necessarily run to perform DNS
  validation when the user starts HTTP/DNS issuance.

  ACME calls use fixed argument arrays, --issue followed by --install-cert.
  The returned files are checked with tls.LoadX509KeyPair and hostname/time
  validation; exit status alone is not treated as proof of a certificate.
  Issuance is capped at 15 minutes per command, honors caller cancellation,
  and on Linux kills the entire subprocess group when cancelled.
  Existing managed certificates are reused with more than 30 days remaining.
  Repeated Resolve calls check renewal; this package does not install cron
  entries or run an autonomous renewal loop. Callers must invoke Resolve
  periodically and reload their TLS configuration when files change.

Validation completed:
  Local RSA and ECDSA self certificate generation, persistence and successful
  HTTPS handshakes with a trusted local certificate.
  Custom certificate validation and rejection of mismatched keys/domains.
  Fake local ACME executables verify HTTP/DNS arguments, ECC installation,
  literal credential delivery, secret redaction, missing/failed output,
  cache reuse and Linux subprocess cancellation.

No real CA issuance or DNS provider operation was performed during development.
The original input executable was not run.
