Redis global IP/CID admission (independent reconstruction)
========================================================
This is newly written compatibility code, not recovered original soga source.
It implements the documented Redis 8+ shared limit behavior with Go's standard
library and an embedded, parameterized Lua script.

API
  New(Options) (*Manager,error)
  Manager.Acquire(context.Context,Request) (release func(),error)
  Manager.Close() error
  errors.Is(err,ErrQuotaExceeded); errors.As(err,*QuotaError)

Request carries UserID, IP, DeviceID, IPLimit and DeviceLimit. A zero
limit disables that dimension; negative limits are rejected. An empty DeviceID disables device counting;
SSR UDP has no authenticated CID and must not invent one. The proxy supplies
the same normalized real-client IP used by its local limiter. DeviceID is
normally "cid:<authenticated client ID>" or the caller's explicit IP identity.
The package hashes identities in Redis keys and never stores user passwords.

New validates local options without requiring an available Redis server.
The caller first enforces its local quota. ErrQuotaExceeded rejects admission.
On a Redis availability error, Acquire still returns an idempotent release
function: a caller choosing the documented local fallback must retain it.
The manager continues renewing/re-registering locally accepted live leases
when Redis recovers. Call release when the actual connection closes; canceling
the supplied context also releases it. Close releases all tracked connections.

Limits are checked together in one Lua invocation using Redis TIME. The script
checks both dimensions before reserving either. Multiple connections/nodes
with the same identity share a slot, but have separate random lease tokens.
Every active lease is renewed. Releasing the last live token retains its
identity for Expiry (default 60 seconds). A crashed process leaves a finite
lease that expires after LeaseTTL plus Expiry. LeaseTTL defaults to 30 seconds;
renewal runs each LeaseTTL/3. Redis outage fallback deliberately cannot enforce
a strict cross-node cap while nodes are disconnected. Upon recovery, existing
connections are counted rather than forcibly evicted; new identities are
denied until the shared count permits them.

Defaults and Redis requirements
- Addr must be host:port. Password uses RESP AUTH; DB uses SELECT.
- TLS verifies the server certificate/name with TLS 1.2 minimum by default.
  TLSConfig permits an explicitly configured private root CA/server name.
- Namespace defaults to "soga:limits:v1". Nodes sharing a DB and namespace
  share the same user quotas. This schema is this reconstruction's own format;
  interoperation with a proprietary soga Redis key format is not claimed.
- INFO server verifies major version >=8 on new connections. The Redis ACL
  must permit AUTH/SELECT/INFO, EVALSHA/EVAL, TIME, ZREMRANGEBYSCORE, ZSCORE,
  ZCARD, ZADD, ZREM, ZRANGE and PEXPIRE. Script-cache flushing is tolerated.
- Connection pool: at most eight idle connections; requests have a bounded
  timeout (default 2 seconds). Renew/release workers are bounded at eight.
  Brief retry cooldown prevents an outage causing a timeout for every lease.
- Standalone Redis is supported. Key hash tags keep each user's script keys in
  one slot, but MOVED/ASK handling and Redis Cluster discovery are not provided.

Integration tests
Set REDIS_SERVER to a real Redis 8+ executable and run:
  go test -race ./redislimit
Without that variable the integration tests explicitly skip; they are never
replaced with an in-memory Redis imitation. Tests start loopback-only temporary
Redis processes with persistence disabled. TLS testing uses a verified local
TLS terminator forwarding to that real Redis server, not a simulated protocol.
No original soga executable or external Redis/CA service is run.

Primary implementation references
https://redis.io/docs/latest/develop/programmability/eval-intro/
https://redis.io/docs/latest/commands/time/
https://redis.io/docs/latest/commands/zadd/
Behavioral reference: bundled docs/other/limit-ip-and-device-num.md.
