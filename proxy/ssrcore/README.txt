SSR compatibility core (independent reconstruction)
==================================================
This package is not recovered original soga source. It adapts the actual server
and client framing/cipher code of ProxyPanel/VNet-SSR, pinned at commit
39f00f978880e825f78e6ca406b1d0ba24dcb95f. The retained source subtree, original
file hashes and GPL-3.0 license are in internal/vnet/. Distribution of this
reconstruction includes those sources and notices.

Public API
- RegisterInbound(*inbound.Registry), RegisterOutbound(*outbound.Registry).
- Type = "ssr"; NewInbound/NewOutbound factory signatures match sing-box.
- Validate(Options), Protocols(), Obfuscators().
- AuthenticatedClientID(ctx) (uint32,bool) exposes a verified TCP auth CID.
- HostForUser(User,pattern,suffix) returns the statically recovered mu Host.
- UnattributedTraffic(ctx) marks opt-in carrier UDP without an ordinary user.

Protocol single-port: Options.SinglePortType="protocol", outer Password is the
node password. Users have positive billing IDs and independent passwords. Optional ProtocolID
separates a uint32 wire UID from the billing ID (zero uses ID). Each UID is
little-endian on wire; router identity remains the billing ID. Authentication completes before any route. Unknown
UIDs, wrong passwords, replayed auth and raw authentication fallback do not route.
For one user per listener, SinglePortType is empty or "none"; exactly one User is
required and its password is the outer cipher key. The parent runtime must create
separate listeners for panel users with separate ports/ciphers.

Obfs single-port: SinglePortType="obfs". Method/Password/Protocol/Obfs come from
the carrier, while each User's own Password/Method/Obfs/Protocol produce its Host:
lowerhex(MD5(decimal billing ID + password + method + obfs + protocol)).
MURegex defaults to "%5m%id.%suffix"; MUSuffix defaults to "microsoft.com".
The first %Nm uses the first min(N,32) digest characters; %id and %suffix are
each replaced once. Host/SNI selects the billing user without changing the
carrier's cipher. ProtocolID is not used in this digest. Invalid/duplicate
hosts fail configuration; unknown incoming hosts do not route. The original
missing-placeholder panic is represented by a validation error.

SSR http_simple/http_post/tls1.2_ticket_auth/tls1.2_ticket_fastauth retain their
actual protocol framing. For origin + a legacy stream cipher, the distinct
simple_obfs_http/simple_obfs_tls transports use the independent simpleobfs
package and official sing-box clients. AEAD + simple-obfs is handled by the
parent proxy's Shadowsocks adapter, not this legacy stream codec.

Obfs single-port UDP does not listen by default. Explicit ObfsUDP=true also
requires a nonnegative CarrierID (zero for synthetic carriers). Such packets use the carrier key and cannot
select an ordinary user from a Host; the router receives CarrierID together
with UnattributedTraffic=true. The caller must retain node limits and omit
ordinary user traffic/quota accounting. No CID is fabricated for UDP.

Supported auth protocols: origin/auth_sha1_v4 for a single user; auth_aes128_md5,
auth_aes128_sha1, auth_chain_a through auth_chain_f for authenticated multiuser.
Obfuscators: plain, http_simple, http_post, tls1.2_ticket_auth and the reference
compatible tls1.2_ticket_fastauth wire variant. Legacy stream ciphers are those
registered in the retained ciphers/stream package. SSR's framed protocols reject
AEAD. origin+none is rejected because it cannot authenticate any user.

Inbound TCP and UDP are passed to the caller's guardedRouter with authenticated
user ID, actual client address and decoded destination. No direct dial bypasses
that router. UDP has authenticated user identity but no authenticated CID. TCP
protocol single-port CID is supplied through context for the central limiter.
All listeners and established/pending sessions close with the lifecycle scope.
UDP associations are bounded at 4096, queue length 32, idle timeout 2 minutes.

OutboundOptions embeds sing-box option.DialerOptions and specifies Server,
ServerPort, Method, Password, Protocol, Obfs, ProtocolParam, ObfsParam. Protocol
single-port clients use ProtocolParam="uid:user-password" and Password=outer
node key. TCP/UDP outbound uses the configured sing-box dialer, including bind
address/detour options; it is not implemented as a direct escape route.

Adaptation and correctness fixes
- Scope replay/auth service per listener; remove mandatory global singleton.
- Synchronize protocol state, writes, reads, close and random number generation.
- Isolate upstream diagnostics in a private discarded logger: authentication
  material and packet dumps do not reach global application logrus.
- Share TLS replay state across each listener; preserve TFO/MPTCP listen flags.
- Reject raw authentication fallback even if an unverified UID was seen first.
- auth_aes128 client maximum frame changed 8129 to reference 8192; dispose
  authenticated server sessions; split password only at the first colon.
- chain_b-f sample table lengths once, not on every loop-condition evaluation;
  use full transport overhead; chain_c thresholds use payload size; chain_f
  XORs the big-endian time bucket into the key, not receive-IV-derived bytes.
- TLS fastauth must not bypass authentication. Use the same authenticated wire
implementation as the pinned Python SSR reference. Fix TLS server hello type,
  ClientHello compression vector order, explicit uint16 ticket lengths, partial
  handshake buffering and coalesced data.
- Buffer partial HTTP response headers. Keep private key/cipher code separate
  from all upstream panel/network/CLI services.

Evidence and tests
See outputs/soga-analysis/runtime-reconstruction/ssr in the analysis deliverable
for full results and pinned independent-reference sources. Tests cover real
loopback TCP/UDP, both authorized users, wrong credentials, large packets,
three-byte framing fragments, outgoing SSR routing and fixed size-table vectors.
An optional TestReferencePythonInterop invokes the pinned original Python auth
implementation, with standard AES/RC4 supplied by Python cryptography; it does
not invoke the original soga executable. It covers AES MD5/SHA1 and chain_a/b,
including the official Python TLS auth/fastauth implementations.
chain_c-f have local network tests and independent C# algorithm vectors, but have
not been tested with an external C# client process. This distinction matters.

Remaining validation limits
The matrix covers real local TCP/UDP and distinct users/keys, not production
panel deployment or every third-party client implementation. Legacy origin
stream ciphers are not authenticated encryption; their protocol limitations
are retained. No authorization/license handshake from the proprietary input
is copied or bypassed.
