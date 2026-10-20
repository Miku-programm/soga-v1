package ssrcore

import "context"

type clientIDKey struct{}
type unattributedKey struct{}

// UnattributedTraffic marks opt-in obfs single-port UDP: carrier credentials
// protect the packet, but this wire format cannot identify an ordinary user.
// Routers must retain node limits while omitting ordinary user accounting and
// user IP/CID quotas. The metadata User identifies the carrier, not its users.
func UnattributedTraffic(ctx context.Context) bool {
	value, _ := ctx.Value(unattributedKey{}).(bool)
	return value
}

// AuthenticatedClientID returns the protocol-authenticated SSR client ID. It is
// only attached to authenticated TCP protocol single-port connections. UDP's
// wire format carries user identity but has no authenticated client ID.
func AuthenticatedClientID(ctx context.Context) (uint32, bool) {
	id, ok := ctx.Value(clientIDKey{}).(uint32)
	return id, ok
}
