package engine

import (
	"errors"
	"fmt"
	"time"

	"reconstructed.local/soga/config"
	"reconstructed.local/soga/panel"
)

func openPanel(c config.Config, id string) (panel.API, func() error, error) {
	opts := panel.Options{Type: c.Type, BaseURL: c.WebapiUrl, APIKey: c.EffectiveWebAPIKey(),
		NodeID: id, NodeType: c.ServerType, SubType: c.SubType}
	switch c.Api {
	case "", "webapi":
		api, err := panel.NewClient(opts)
		return api, nil, err
	case "db":
		if c.DbPort < 1 || c.DbPort > 65535 || c.DbMaxConn < 0 || c.DbMaxConn > 100000 ||
			c.DbMaxIdleConn < 0 || c.DbMaxIdleConn > 100000 || c.DbMaxIdleTime < 0 || c.DbMaxIdleTime > 525600 {
			return nil, nil, errors.New("invalid database port or connection-pool limits")
		}
		tlsType := "none"
		if c.WhmcsTls {
			tlsType = "tls"
		}
		settings := panel.MySQLOptions{
			Host: c.DbHost, Port: int(c.DbPort), Database: c.DbName, User: c.DbUser, Password: c.DbPassword,
			MaxOpenConns: int(c.DbMaxConn), MaxIdleConns: int(c.DbMaxIdleConn),
			MaxIdleTime: time.Duration(c.DbMaxIdleTime) * time.Minute, TrafficRate: c.WhmcsRate,
			LocalNode: panel.NodeConfig{Port: int(c.WhmcsPort), Cipher: c.WhmcsMethod, Method: c.WhmcsMethod,
				Password: c.WhmcsPassword, Protocol: c.WhmcsProtocol, Obfs: c.WhmcsObfs,
				StreamType: c.WhmcsNet, TLSType: tlsType, AlterID: int(c.WhmcsAlterId),
				Path: c.WhmcsWsPath, ServiceName: c.WhmcsServiceName},
		}
		api, err := panel.NewMySQL(opts, settings)
		if err != nil {
			return nil, nil, err
		}
		return api, api.Close, nil
	default:
		return nil, nil, fmt.Errorf("unknown api mode %q", c.Api)
	}
}
