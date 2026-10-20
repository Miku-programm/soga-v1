package proxy

import (
	"context"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/certificate"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	boxservice "github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport/local"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/protocol/anytls"
	"github.com/sagernet/sing-box/protocol/direct"
	"github.com/sagernet/sing-box/protocol/http"
	"github.com/sagernet/sing-box/protocol/hysteria"
	"github.com/sagernet/sing-box/protocol/hysteria2"
	"github.com/sagernet/sing-box/protocol/shadowsocks"
	"github.com/sagernet/sing-box/protocol/socks"
	"github.com/sagernet/sing-box/protocol/trojan"
	"github.com/sagernet/sing-box/protocol/vless"
	"github.com/sagernet/sing-box/protocol/vmess"
	"github.com/sagernet/sing/service"
	"reconstructed.local/soga/proxy/ssrcore"
)

// Register only supported protocols; unused system/tunnel/services are absent.
func protocolContext(ctx context.Context, m *meter, hook func(Request) error, transform func(context.Context, Request) (Request, error), limiter *Limiter, mieruTransport string, udpTimeout time.Duration, inspectionArgs ...inspectionOptions) context.Context {
	var inspection inspectionOptions
	if len(inspectionArgs) > 0 {
		inspection = inspectionArgs[0]
	}
	in := inbound.NewRegistry()
	vmess.RegisterInbound(in)
	vless.RegisterInbound(in)
	trojan.RegisterInbound(in)
	shadowsocks.RegisterInbound(in)
	anytls.RegisterInbound(in)
	hysteria.RegisterInbound(in)
	hysteria2.RegisterInbound(in)
	ssrcore.RegisterInbound(in)
	inbound.Register[mieruOptions](in, "mieru", newMieruInbound)
	inbound.Register[xrayOptions](in, "xray-core", newXrayInbound)
	inbound.Register[tlsServiceOptions](in, "tls-service", newTLSServiceInbound)
	inbound.Register[shadowsocksOptions](in, "ss-service", newShadowsocksInbound)
	out := outbound.NewRegistry()
	direct.RegisterOutbound(out)
	socks.RegisterOutbound(out)
	http.RegisterOutbound(out)
	vmess.RegisterOutbound(out)
	vless.RegisterOutbound(out)
	trojan.RegisterOutbound(out)
	shadowsocks.RegisterOutbound(out)
	anytls.RegisterOutbound(out)
	hysteria.RegisterOutbound(out)
	hysteria2.RegisterOutbound(out)
	ssrcore.RegisterOutbound(out)
	dnsRegistry := dns.NewTransportRegistry()
	local.RegisterTransport(dnsRegistry)
	return box.Context(ctx, &guardedRegistry{Registry: in, meter: m, hook: hook, transform: transform, limiter: limiter, mieruTransport: mieruTransport, udpTimeout: udpTimeout, inspection: inspection}, out, endpoint.NewRegistry(),
		dnsRegistry, boxservice.NewRegistry(), certificate.NewRegistry())
}

type guardedRegistry struct {
	*inbound.Registry
	meter          *meter
	hook           func(Request) error
	transform      func(context.Context, Request) (Request, error)
	limiter        *Limiter
	mieruTransport string
	udpTimeout     time.Duration
	inspection     inspectionOptions
}

func (r *guardedRegistry) Create(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag, protocol string, options any) (adapter.Inbound, error) {
	return r.Registry.Create(ctx, &guardedRouter{Router: router, meter: r.meter, hook: r.hook, transform: r.transform,
		limiter: r.limiter, protocol: protocol, mieruTransport: r.mieruTransport, udpTimeout: r.udpTimeout,
		inspection: r.inspection,
		outbound:   service.FromContext[adapter.OutboundManager](ctx), connection: service.FromContext[adapter.ConnectionManager](ctx)}, logger, tag, protocol, options)
}
