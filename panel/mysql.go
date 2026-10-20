package panel

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"strconv"
	"time"

	mysql "github.com/go-sql-driver/mysql"
)

// MySQLOptions describes the documented api=db connection. LocalNode and
// TrafficRate are the whmcs_* settings, not WebAPI fallbacks.
type MySQLOptions struct {
	Host                       string
	Port                       int
	Database, User, Password   string
	LocalNode                  NodeConfig
	TrafficRate                float64
	MaxOpenConns, MaxIdleConns int
	MaxIdleTime                time.Duration
}
type MySQL struct {
	db       *sql.DB
	opts     Options
	settings MySQLOptions
	nodeID   int64
}

func NewMySQL(opts Options, settings MySQLOptions) (*MySQL, error) {
	if opts.Type != "sspanel-uim" && opts.Type != "whmcs" {
		return nil, fmt.Errorf("%w: %s has no recovered MySQL adapter", ErrUnsupported, opts.Type)
	}
	opts.NodeType = NormalizeNodeType(opts.NodeType)
	switch opts.NodeType {
	case "vmess", "trojan", "shadowsocks", "shadowsocksr":
	default:
		return nil, fmt.Errorf("%w: MySQL protocol %s", ErrUnsupported, opts.NodeType)
	}
	id, err := strconv.ParseInt(opts.NodeID, 10, 64)
	if err != nil || id <= 0 {
		return nil, errors.New("MySQL node ID must be positive")
	}
	if settings.Host == "" || settings.Database == "" || settings.User == "" {
		return nil, errors.New("MySQL host, database and user are required")
	}
	if settings.Port == 0 {
		settings.Port = 3306
	}
	if settings.Port < 1 || settings.Port > 65535 {
		return nil, errors.New("invalid MySQL port")
	}
	if settings.MaxOpenConns == 0 {
		settings.MaxOpenConns = 4
	}
	if settings.MaxIdleConns == 0 {
		settings.MaxIdleConns = 4
	}
	if settings.MaxIdleTime == 0 {
		settings.MaxIdleTime = 480 * time.Minute
	}
	if settings.MaxOpenConns < 0 || settings.MaxIdleConns < 0 || settings.MaxIdleTime < 0 {
		return nil, errors.New("MySQL pool settings cannot be negative")
	}
	cfg := mysql.NewConfig()
	cfg.Net = "tcp"
	cfg.Addr = net.JoinHostPort(settings.Host, strconv.Itoa(settings.Port))
	cfg.User = settings.User
	cfg.Passwd = settings.Password
	cfg.DBName = settings.Database
	cfg.ParseTime = true
	cfg.Timeout = 30 * time.Second
	cfg.ReadTimeout = 30 * time.Second
	cfg.WriteTimeout = 30 * time.Second
	connector, err := mysql.NewConnector(cfg)
	if err != nil {
		return nil, errors.New("invalid MySQL connection settings")
	}
	db := sql.OpenDB(connector)
	db.SetMaxOpenConns(settings.MaxOpenConns)
	db.SetMaxIdleConns(settings.MaxIdleConns)
	db.SetConnMaxIdleTime(settings.MaxIdleTime)
	return &MySQL{db: db, opts: opts, settings: settings, nodeID: id}, nil
}
func (c *MySQL) Close() error { return c.db.Close() }
func (c *MySQL) Capabilities() Capabilities {
	return Capabilities{AliveIPs: c.opts.Type == "sspanel-uim", AuditLogs: c.opts.Type == "sspanel-uim", Status: c.opts.Type == "sspanel-uim"}
}
func (c *MySQL) FetchAuditRules(context.Context) ([]AuditRule, error) { return nil, ErrUnsupported }
func (c *MySQL) FetchWhiteList(context.Context) ([]string, error)     { return nil, ErrUnsupported }

// WHMCS queries below are byte-for-byte recovered constant strings. SSPanel's
// parameterized selection uses the recovered field list and WHERE predicates.
const whmcsSSUsers = "select id, u, d, transfer_enable, uuid, speedlimitss from user where enable = 1 and u + d < transfer_enable"
const whmcsSSRUsers = "select pid, u, d, transfer_enable, port, passwd from user where enable = 1 and u + d < transfer_enable"
const whmcsUUIDUsers = "select id, u, d, transfer_enable, uuid from user where enable = 1 and u + d < transfer_enable"
const ssNodeQuery = "select server, node_speedlimit, mu_only from ss_node where id = ?"
const ssNodeEligibility = "select node_bandwidth_limit, node_bandwidth, node_group, node_class from ss_node where id = ?"
const ssUserFields = "id, passwd, u, d, transfer_enable, node_speedlimit, node_connector, port, method, protocol, protocol_param, obfs, obfs_param, is_multi_user"

func (c *MySQL) FetchNode(ctx context.Context) (Node, error) {
	if c.opts.Type == "whmcs" {
		cfg := c.settings.LocalNode
		if cfg.Port < 1 || cfg.Port > 65535 {
			return Node{}, errors.New("WHMCS database mode requires valid whmcs_port")
		}
		if cfg.Method == "" {
			cfg.Method = cfg.Cipher
		}
		if cfg.Cipher == "" {
			cfg.Cipher = cfg.Method
		}
		if cfg.StreamType == "" {
			cfg.StreamType = "tcp"
		}
		if cfg.TLSType == "" {
			cfg.TLSType = "none"
		}
		switch c.opts.NodeType {
		case "trojan":
			cfg.StreamType = "tcp"
			cfg.TLSType = "tls"
		case "shadowsocks":
			if cfg.Method == "" {
				return Node{}, errors.New("WHMCS Shadowsocks requires whmcs_method")
			}
		case "shadowsocksr":
			if cfg.Method == "" || cfg.Password == "" || cfg.Protocol == "" || cfg.Obfs == "" {
				return Node{}, errors.New("WHMCS SSR requires whmcs_method/password/protocol/obfs")
			}
			cfg.SinglePortType = "protocol"
		}
		raw, _ := json.Marshal(cfg)
		return Node{Config: cfg, RawConfig: raw}, nil
	}
	var server sql.NullString
	var speed sql.NullFloat64
	var mu sql.NullInt64
	if err := c.db.QueryRowContext(ctx, ssNodeQuery, c.nodeID).Scan(&server, &speed, &mu); err != nil {
		return Node{}, fmt.Errorf("SSPanel node lookup: %w", err)
	}
	cfg, err := parseLegacySSPanel(c.opts.NodeType, server.String)
	if err != nil {
		return Node{}, err
	}
	if cfg.StreamType == "" {
		cfg.StreamType = "tcp"
	}
	if cfg.TLSType == "" {
		cfg.TLSType = "none"
	}
	if c.opts.NodeType == "trojan" {
		cfg.TLSType = "tls"
	}
	cfg.OnlyMultiUserPorts = mu.Int64 == 1
	if c.opts.NodeType == "shadowsocks" {
		users, err := c.fetchSSPanelUsers(ctx)
		if err != nil {
			return Node{}, err
		}
		if err = applySSPanelPasswordCarrier(&cfg, users); err != nil {
			return Node{}, err
		}
	}
	if !cfg.MultiUserPorts && (cfg.Port < 1 || cfg.Port > 65535) {
		return Node{}, errors.New("SSPanel node has invalid port")
	}
	raw, _ := json.Marshal(map[string]any{"server": server.String, "node_speedlimit": speed.Float64, "mu_only": mu.Int64})
	rules, err := c.FetchDetectRules(ctx)
	if err != nil {
		return Node{}, err
	}
	return Node{Config: cfg, Basic: Basic{SpeedLimit: max(0, speed.Float64)}, RawConfig: raw, Policy: SSPanelPolicy(rules)}, nil
}
func (c *MySQL) FetchUsers(ctx context.Context) ([]User, error) {
	if c.opts.Type == "whmcs" {
		return c.fetchWHMCSUsers(ctx)
	}
	return c.fetchSSPanelUsers(ctx)
}
func (c *MySQL) fetchWHMCSUsers(ctx context.Context) ([]User, error) {
	query := whmcsUUIDUsers
	if c.opts.NodeType == "shadowsocks" {
		query = whmcsSSUsers
	}
	if c.opts.NodeType == "shadowsocksr" {
		query = whmcsSSRUsers
	}
	rows, err := c.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("WHMCS users query: %w", err)
	}
	defer rows.Close()
	users := make([]User, 0)
	for rows.Next() {
		var id, u, d, quota int64
		var credential sql.NullString
		var speed, port sql.NullInt64
		args := []any{&id, &u, &d, &quota, &credential}
		if c.opts.NodeType == "shadowsocks" {
			args = append(args, &speed)
		} else if c.opts.NodeType == "shadowsocksr" {
			args = []any{&id, &u, &d, &quota, &port, &credential}
		}
		if err = rows.Scan(args...); err != nil {
			return nil, fmt.Errorf("WHMCS user row: %w", err)
		}
		if !credential.Valid {
			continue
		} // Original logs and skips SQL NULL credentials.
		user := User{ID: id, SpeedLimit: float64(max(0, min(10000, speed.Int64))), Port: int(port.Int64)}
		if c.opts.NodeType == "shadowsocksr" {
			if port.Int64 <= 0 || port.Int64 > 1<<32-1 {
				return nil, errors.New("WHMCS SSR port is outside the protocol UID range")
			}
			// UpdatePanelUser 0x18221e5 uses port for WHMCS/ProxyPanel;
			// ID remains the pid used by the traffic UPDATE statement.
			user.ProtocolID = uint32(port.Int64)
		}
		switch c.opts.NodeType {
		case "vmess":
			user.UUID = credential.String
		case "trojan", "shadowsocks", "shadowsocksr":
			user.Password = credential.String
		}
		users = append(users, user)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("WHMCS users iteration: %w", err)
	}
	return users, nil
}
func (c *MySQL) fetchSSPanelUsers(ctx context.Context) ([]User, error) {
	var limit, used, group, class sql.NullInt64
	if err := c.db.QueryRowContext(ctx, ssNodeEligibility, c.nodeID).Scan(&limit, &used, &group, &class); err != nil {
		return nil, fmt.Errorf("SSPanel node eligibility: %w", err)
	}
	if limit.Int64 > 0 && limit.Int64 <= used.Int64 {
		return []User{}, nil
	}
	// Introspection is compatibility infrastructure. The original also probes for
	// uuid once, but this implementation avoids process-global cross-DB caching.
	var hasUUID int
	if err := c.db.QueryRowContext(ctx, "select count(*) from information_schema.columns where table_schema = ? and table_name = 'user' and column_name = 'uuid'", c.settings.Database).Scan(&hasUUID); err != nil {
		return nil, err
	}
	fields := ssUserFields
	if hasUUID > 0 {
		fields += ", uuid"
	}
	query := "select " + fields + " from user where enable = 1 and expire_in > ? and u + d < transfer_enable and "
	args := []any{time.Now().Format("2006-01-02 15:04:05"), class.Int64}
	if group.Int64 == 0 {
		query += "(class >= ? or is_admin = 1)"
	} else {
		query += "((class >= ? and node_group >= ?) or is_admin = 1)"
		args = append(args, group.Int64)
	}
	rows, err := c.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("SSPanel users query: %w", err)
	}
	defer rows.Close()
	users := make([]User, 0)
	for rows.Next() {
		var id, u, d, quota, connector, port, mu sql.NullInt64
		var password, method, protocol, protocolParam, obfs, obfsParam, uuid sql.NullString
		var speed sql.NullFloat64
		args := []any{&id, &password, &u, &d, &quota, &speed, &connector, &port, &method, &protocol, &protocolParam, &obfs, &obfsParam, &mu}
		if hasUUID > 0 {
			args = append(args, &uuid)
		}
		if err = rows.Scan(args...); err != nil {
			return nil, err
		}
		if math.IsNaN(speed.Float64) || math.IsInf(speed.Float64, 0) {
			return nil, errors.New("SSPanel user has non-finite speed")
		}
		user := User{ID: id.Int64, Password: password.String, UUID: uuid.String, SpeedLimit: max(0, min(10000, speed.Float64)), DeviceLimit: int(max(0, connector.Int64)), Port: int(port.Int64), Method: method.String, Protocol: protocol.String, ProtocolParam: protocolParam.String, Obfs: obfs.String, ObfsParam: obfsParam.String}
		user.IsMultiUser = int(mu.Int64)
		if user.IsMultiUser < 0 || user.IsMultiUser > 2 {
			return nil, fmt.Errorf("%w: SSPanel is_multi_user=%d", ErrUnsupported, user.IsMultiUser)
		}
		if (c.opts.NodeType == "vmess" || c.opts.NodeType == "trojan") && user.UUID == "" {
			user.UUID = SSPanelLegacyUUID(user.ID, user.Password)
		}
		if c.opts.NodeType == "trojan" {
			user.Password = user.UUID
		}
		users = append(users, user)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	return users, nil
}
