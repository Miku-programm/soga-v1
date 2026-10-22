package engine

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"testing"

	"reconstructed.local/soga/config"
	"reconstructed.local/soga/panel"
	"reconstructed.local/soga/proxy"
)

type policyPanel struct {
	panel.API
	node    panel.Node
	fail    bool
	reports [][]panel.PolicyDenial
	users   []panel.User
	traffic map[int64]int64
}

func (p *policyPanel) Capabilities() panel.Capabilities              { return panel.Capabilities{} }
func (p *policyPanel) FetchNode(context.Context) (panel.Node, error) { return p.node, nil }
func (p *policyPanel) FetchUsers(context.Context) ([]panel.User, error) {
	if p.users != nil {
		return p.users, nil
	}
	return []panel.User{{ID: 23, UUID: fixtureUUID}}, nil
}
func (p *policyPanel) ReportTraffic(_ context.Context, rows []panel.Traffic) error {
	if p.traffic == nil {
		p.traffic = map[int64]int64{}
	}
	for _, row := range rows {
		p.traffic[row.ID] += row.Upload + row.Download
	}
	return nil
}
func (p *policyPanel) ReportPolicyDenials(_ context.Context, v []panel.PolicyDenial) error {
	p.reports = append(p.reports, append([]panel.PolicyDenial(nil), v...))
	if p.fail {
		return errors.New("fixture temporary failure")
	}
	return nil
}
func TestPanelAllowPolicyAndDenialRetry(t *testing.T) {
	reservation, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := reservation.Addr().(*net.TCPAddr).Port
	reservation.Close()
	api := &policyPanel{node: panel.Node{Config: panel.NodeConfig{Port: port}, Policy: &panel.Policy{
		Mode: "allow", Rules: []panel.PolicyRule{{ID: 9, Rule: "ip:192.0.2.0/24"}},
	}}}
	c := config.Defaults()
	c.ServerType, c.Listen = "vmess", "127.0.0.1"
	c.CheckInterval, c.SubmitInterval, c.RandomIntervalRange = 3600, 3600, 0
	c.IpUserCacheSaveDir = t.TempDir()
	n, err := StartNode(context.Background(), Options{Config: c, NodeID: "1", API: api, Paths: Paths{StateDir: t.TempDir()}, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close(context.Background())
	allowed := proxy.Request{UserID: 23, Network: "tcp", Source: "127.0.0.1:123", Destination: "192.0.2.5:443"}
	if _, err = n.transform(context.Background(), allowed); err != nil {
		t.Fatal(err)
	}
	denied := allowed
	denied.Destination = "198.51.100.5:443"
	if _, err = n.transform(context.Background(), denied); err == nil {
		t.Fatal("allow-only default did not deny")
	}
	api.fail = true
	if err = n.Push(context.Background()); err == nil {
		t.Fatal("report failure lost")
	}
	api.fail = false
	if err = n.Push(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(api.reports) != 2 || len(api.reports[1]) != 1 || api.reports[1][0].UserID != 23 || api.reports[1][0].Rule != "panel_allow_list" {
		t.Fatal(api.reports)
	}
	if err = n.Push(context.Background()); err != nil || len(api.reports) != 2 {
		t.Fatal("ACKed denial repeated", err)
	}
	// An opt-in SSR carrier UDP request has no authenticated user to report.
	denied.Unattributed = true
	if _, err = n.transform(context.Background(), denied); err == nil {
		t.Fatal("carrier bypassed safety policy")
	}
	if err = n.Push(context.Background()); err != nil || len(api.reports) != 2 {
		t.Fatal("carrier counted as ordinary user", err)
	}
}

func TestUDPDecisionCarriesPacketCheck(t *testing.T) {
	reservation, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := reservation.Addr().(*net.TCPAddr).Port
	reservation.Close()
	api := &policyPanel{node: panel.Node{Config: panel.NodeConfig{Port: port}}}
	c := config.Defaults()
	c.ServerType, c.Listen = "vmess", "127.0.0.1"
	c.CheckInterval, c.SubmitInterval, c.RandomIntervalRange = 3600, 3600, 0
	c.IpUserCacheSaveDir = t.TempDir()
	c.ForbiddenBitTorrent = true
	n, err := StartNode(context.Background(), Options{Config: c, NodeID: "1", API: api, Paths: Paths{StateDir: t.TempDir()}, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close(context.Background())
	udp := proxy.Request{UserID: 23, Network: "udp", Source: "127.0.0.1:123", Destination: "192.0.2.5:6881"}
	req, err := n.transform(context.Background(), udp)
	if err != nil {
		t.Fatal(err)
	}
	if req.PacketCheck == nil {
		t.Fatal("UDP decision has no payload check while forbidden_bit_torrent is on")
	}
	if err := req.PacketCheck([]byte("plain game data")); err != nil {
		t.Fatal("ordinary payload denied", err)
	}
	if err := req.PacketCheck([]byte("\x13BitTorrent protocol")); err == nil {
		t.Fatal("BitTorrent handshake in a later packet was accepted")
	}
	tcp := udp
	tcp.Network = "tcp"
	if req, err = n.transform(context.Background(), tcp); err != nil || req.PacketCheck != nil {
		t.Fatal("TCP decisions need no per-packet check", err)
	}
}
