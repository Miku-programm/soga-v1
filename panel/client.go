package panel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

var ErrUnsupported = errors.New("panel operation is not implemented for this adapter")

type HTTPError struct {
	Endpoint string
	Status   int
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("panel %s returned HTTP %d", e.Endpoint, e.Status)
}

type APIError struct {
	Code    int
	Message string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("panel rejected report (code %d): %s", e.Code, e.Message)
}

type cacheEntry struct {
	mu   sync.Mutex
	etag string
	body []byte
}

type Client struct {
	base       *url.URL
	opts       Options
	http       *http.Client
	cacheMu    sync.Mutex
	cache      map[string]*cacheEntry
	uniProxy   bool
	ppanel     bool
	proxyPanel bool
	sspanel    bool
	whmcs      bool
}

// NewClient selects a documented compatibility adapter. No network request is
// performed until a Fetch or Report method is called.
func NewClient(opts Options) (API, error) {
	if opts.Type == "dj" {
		return NewDJ(opts)
	}
	if opts.Type == "v2raysocks" {
		return NewV2RaySocks(opts)
	}
	if opts.Type == "whmcs" {
		return NewWHMCS(opts)
	}
	if opts.Type == "sspanel-uim" {
		return NewSSPanel(opts)
	}
	if opts.Type == "ppanel" {
		return NewPPanel(opts)
	}
	if opts.Type == "proxypanel" {
		return NewProxyPanel(opts)
	}
	if opts.Type == "v2board" || opts.Type == "xboard" || opts.Type == "xiaov2board" {
		return NewUniProxy(opts)
	}
	if opts.Type != "" && opts.Type != "soga-v1" {
		return nil, fmt.Errorf("%w: %s", ErrUnsupported, opts.Type)
	}
	return NewSogaV1(opts)
}

func NormalizeNodeType(t string) string {
	switch strings.ToLower(t) {
	case "v2ray", "vmess":
		return "vmess"
	case "ss", "shadowsocks":
		return "shadowsocks"
	case "ssr", "shadowsocksr":
		return "shadowsocksr"
	case "hysteria2", "hysteria":
		return "hysteria"
	default:
		return strings.ToLower(t)
	}
}

func NewSogaV1(opts Options) (*Client, error) {
	base, err := url.Parse(opts.BaseURL)
	if err != nil || (base != nil && (base.Scheme != "http" && base.Scheme != "https" || base.Host == "" || base.Fragment != "")) {
		return nil, errors.New("panel base URL must be an absolute HTTP(S) URL without a fragment")
	}
	if opts.NodeID == "" {
		return nil, errors.New("panel node ID is required")
	}
	opts.NodeType = NormalizeNodeType(opts.NodeType)
	switch opts.NodeType {
	case "vmess", "vless", "shadowsocks", "shadowsocksr", "trojan", "hysteria", "anytls", "mieru":
	default:
		return nil, fmt.Errorf("unsupported node type %q", opts.NodeType)
	}
	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	return &Client{base: base, opts: opts, http: client, cache: make(map[string]*cacheEntry)}, nil
}

func (c *Client) endpoint(path string) string {
	u := *c.base
	u.Path = strings.TrimRight(u.Path, "/") + path
	if u.RawPath != "" {
		u.RawPath = strings.TrimRight(u.RawPath, "/") + path
	}
	return u.String()
}

func (c *Client) request(ctx context.Context, method, path string, body []byte) (*http.Request, error) {
	requestPath := path
	if c.whmcs {
		requestPath = "/web_api/"
	}
	req, err := http.NewRequestWithContext(ctx, method, c.endpoint(requestPath), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if c.whmcs {
		query := req.URL.Query()
		query.Set("token", c.opts.APIKey)
		query.Set("node_id", c.opts.NodeID)
		nodeType := c.opts.NodeType
		if nodeType == "vmess" || nodeType == "vless" {
			nodeType = "v2ray"
		}
		if nodeType == "hysteria" {
			nodeType = "hysteria2"
		}
		query.Set("node_type", nodeType)
		query.Set("act", path)
		req.URL.RawQuery = query.Encode()
	} else if c.sspanel {
		query := req.URL.Query()
		query.Set("key", c.opts.APIKey)
		query.Set("node_id", c.opts.NodeID)
		req.URL.RawQuery = query.Encode()
	} else if c.proxyPanel {
		req.Header.Set("key", c.opts.APIKey)
		req.Header.Set("timestamp", fmt.Sprintf("%d", time.Now().Unix()))
	} else if c.ppanel {
		query := req.URL.Query()
		query.Set("secret_key", c.opts.APIKey)
		query.Set("server_id", c.opts.NodeID)
		query.Set("protocol", c.opts.NodeType)
		req.URL.RawQuery = query.Encode()
	} else if c.uniProxy {
		query := req.URL.Query()
		query.Set("token", c.opts.APIKey)
		query.Set("node_id", c.opts.NodeID)
		nodeType := c.opts.NodeType
		if c.opts.Type == "xiaov2board" {
			if nodeType == "vmess" {
				nodeType = "v2ray"
			}
			if nodeType == "hysteria" {
				nodeType = "hysteria2"
			}
			if c.opts.SubType == "v2node" {
				nodeType = "v2node"
			}
		}
		query.Set("node_type", nodeType)
		req.URL.RawQuery = query.Encode()
	} else {
		req.Header.Set("API-KEY", c.opts.APIKey)
		req.Header.Set("NODE-ID", c.opts.NodeID)
		req.Header.Set("NODE-TYPE", c.opts.NodeType)
	}
	req.Header.Set("Accept", "application/json")
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
	}
	return req, nil
}

func (c *Client) cached(path string) *cacheEntry {
	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()
	if c.cache[path] == nil {
		c.cache[path] = &cacheEntry{}
	}
	return c.cache[path]
}

const maxResponseBytes = 32 << 20 // Local resource bound, not a recovered original constant.

func readResponse(resp *http.Response) ([]byte, error) {
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxResponseBytes {
		return nil, errors.New("panel response exceeds 32 MiB")
	}
	return body, nil
}

// get serializes each endpoint's ETag transaction. Cached JSON is decoded again,
// so mutations to returned slices cannot modify the cache or future snapshots.
func (c *Client) get(ctx context.Context, path string, decode func([]byte) error) error {
	cache := c.cached(path)
	cache.mu.Lock()
	defer cache.mu.Unlock()
	req, err := c.request(ctx, http.MethodGet, path, nil)
	if err != nil {
		return err
	}
	if cache.etag != "" {
		req.Header.Set("If-None-Match", cache.etag)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("panel GET %s: %w", path, transportCause(err))
	}
	body, err := readResponse(resp)
	if err != nil {
		return fmt.Errorf("panel GET %s: %w", path, err)
	}
	if resp.StatusCode == http.StatusNotModified {
		if cache.etag == "" || cache.body == nil {
			return fmt.Errorf("panel GET %s: 304 without cached representation", path)
		}
		return decode(cache.body)
	}
	if resp.StatusCode != http.StatusOK {
		return &HTTPError{Endpoint: path, Status: resp.StatusCode}
	}
	if err := decode(body); err != nil {
		return fmt.Errorf("panel GET %s: %w", path, err)
	}
	cache.body = append(cache.body[:0], body...)
	cache.etag = resp.Header.Get("ETag")
	return nil
}

func (c *Client) post(ctx context.Context, path string, value any) error {
	body, err := json.Marshal(value)
	if err != nil {
		return err
	}
	req, err := c.request(ctx, http.MethodPost, path, body)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("panel POST %s: %w", path, transportCause(err))
	}
	body, err = readResponse(resp)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return &HTTPError{Endpoint: path, Status: resp.StatusCode}
	}
	// WHMCS's original report wrapper 0x175c0e0 does not decode an application
	// acknowledgement. We additionally require HTTP 200 above.
	if c.whmcs && c.opts.Type != "v2raysocks" {
		return nil
	}
	var ack struct {
		Code    *int            `json:"code"`
		Message string          `json:"message"`
		Data    json.RawMessage `json:"data"`
		Msg     string          `json:"msg"`
		Status  string          `json:"status"`
		Ret     *int            `json:"ret"`
	}
	if err := json.Unmarshal(body, &ack); err != nil {
		return fmt.Errorf("panel POST %s: invalid acknowledgement: %w", path, err)
	}
	if c.opts.Type == "v2raysocks" {
		if ack.Msg != "ok" || ack.Ret == nil || *ack.Ret != 200 {
			return fmt.Errorf("panel POST %s: expected msg=ok and ret=200", path)
		}
		return nil
	}
	if c.sspanel {
		if ack.Ret == nil || *ack.Ret != 1 {
			return fmt.Errorf("panel POST %s: expected ret=1", path)
		}
		return nil
	}
	if c.proxyPanel {
		if ack.Status != "success" || ack.Code == nil || *ack.Code != 200 {
			return fmt.Errorf("panel POST %s: expected status=success and code=200", path)
		}
		return nil
	}
	if c.ppanel {
		if ack.Code == nil {
			return fmt.Errorf("panel POST %s: acknowledgement lacks code", path)
		}
		if *ack.Code != 200 {
			return &APIError{Code: *ack.Code, Message: ack.Msg}
		}
		return nil
	}
	if c.uniProxy {
		if ack.Code != nil && *ack.Code != 0 {
			return &APIError{Code: *ack.Code, Message: ack.Message}
		}
		var success bool
		if json.Unmarshal(ack.Data, &success) != nil || !success {
			return fmt.Errorf("panel POST %s: acknowledgement lacks data=true", path)
		}
		return nil
	}
	// Requiring the field is deliberately stricter than Go's zero-value decode
	// in the original, preventing {} or null from acknowledging an outbox.
	if ack.Code == nil {
		return fmt.Errorf("panel POST %s: acknowledgement lacks code", path)
	}
	if *ack.Code != 0 {
		return &APIError{Code: *ack.Code, Message: ack.Message}
	}
	return nil
}

// net/http wraps failures in url.Error containing the query token. Preserve the
// actual cause for errors.Is while omitting the credential-bearing URL.
func transportCause(err error) error {
	for {
		u, ok := err.(*url.Error)
		if !ok {
			return err
		}
		err = u.Err
	}
}

func (c *Client) FetchNode(ctx context.Context) (node Node, err error) {
	err = c.get(ctx, "/api/v1/node", func(body []byte) error {
		if err := json.Unmarshal(body, &node); err != nil {
			return err
		}
		if len(node.RawConfig) == 0 || node.Config.Port < 1 || node.Config.Port > 65535 {
			return errors.New("node config must contain a port from 1 to 65535")
		}
		return nil
	})
	return
}

func decodeArray[T any](body []byte, dst *[]T) error {
	if err := json.Unmarshal(body, dst); err != nil {
		return err
	}
	if *dst == nil {
		return errors.New("expected JSON array, got null")
	}
	return nil
}

func (c *Client) FetchUsers(ctx context.Context) (users []User, err error) {
	err = c.get(ctx, "/api/v1/users", func(body []byte) error { return decodeArray(body, &users) })
	return
}

func (c *Client) FetchAuditRules(ctx context.Context) (rules []AuditRule, err error) {
	err = c.get(ctx, "/api/v1/audit_rules", func(body []byte) error { return decodeArray(body, &rules) })
	return
}

func (c *Client) FetchWhiteList(ctx context.Context) (rules []string, err error) {
	err = c.get(ctx, "/api/v1/white_list", func(body []byte) error { return decodeArray(body, &rules) })
	return
}

func nonNil[T any](items []T) []T {
	if items == nil {
		return []T{}
	}
	return items
}

func (c *Client) ReportTraffic(ctx context.Context, traffic []Traffic) error {
	return c.post(ctx, "/api/v1/traffic", nonNil(traffic))
}

func (c *Client) ReportAliveIPs(ctx context.Context, alive []AliveIP) error {
	return c.post(ctx, "/api/v1/alive_ip", nonNil(alive))
}

func (c *Client) ReportAuditLogs(ctx context.Context, logs []AuditLog) error {
	seen := make(map[AuditLog]bool, len(logs))
	deduplicated := make([]AuditLog, 0, len(logs))
	for _, item := range logs {
		if !seen[item] {
			deduplicated = append(deduplicated, item)
			seen[item] = true
		}
	}
	return c.post(ctx, "/api/v1/audit_log", deduplicated)
}

func (c *Client) ReportStatus(ctx context.Context, status Status) error {
	return c.post(ctx, "/api/v1/status", status)
}
