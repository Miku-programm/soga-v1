package engine

import (
	"errors"

	"reconstructed.local/soga/config"
)

// These fields select a separate configuration service, not soga_key licensing.
// The supplied binary confirms a mode log, but no request/response contract was
// recovered. Reject explicit use before opening a panel or exposing a listener.
func validatePanelConfigService(c config.Config) error {
	if c.SogaPanelUrl != "" || c.SogaPanelKey != "" {
		return errors.New("soga_panel_url/soga_panel_key select the Soga panel configuration-sync service, not commercial licensing; its HTTP contract has not been recovered, so automatic reporting/loading is not implemented; clear both fields and configure type/api/webapi_url/webapi_key/node_id directly")
	}
	return nil
}
