package engine

import "reconstructed.local/soga/accounting"

type Snapshot struct {
	NodeID                         string
	Protocol                       string
	Users                          int
	Listeners                      int
	Upload, Download               float64
	PendingUpload, PendingDownload float64
}

// Snapshot reports aggregate counters and deliberately excludes credentials,
// user IDs and destination records from the monitoring endpoint.
func (n *Node) Snapshot() (Snapshot, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	s := Snapshot{NodeID: n.opts.NodeID, Protocol: n.opts.Config.NormalizedServerType(), Users: len(n.users), Listeners: len(n.servers)}
	totals, err := n.counters()
	if err != nil {
		return s, err
	}
	add := func(value accounting.Counters) {
		s.Upload += float64(value.Upload)
		s.Download += float64(value.Download)
	}
	for _, value := range totals {
		add(value)
	}
	for _, value := range n.ledger.Batch() {
		s.PendingUpload += float64(value.Upload)
		s.PendingDownload += float64(value.Download)
	}
	return s, nil
}
