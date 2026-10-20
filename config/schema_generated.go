// Code generated from recovered Go RTTI; DO NOT EDIT FIELD LAYOUT BY HAND.
// This is an analyst-named, flattened schema, not original soga source.
// Original Go int fields use int64 here to preserve the target's 8-byte width.
// JSON tags are an added serialization interface; conf/default tags are recovered.
package config

type Config struct {
	// ftLBcUpmkQ.tUl2hoOYI0Ao.QpeDOsW; tag file offset 0x31626ae
	AccessLogClickhouseAddr string `conf:"access_log_clickhouse_addr" json:"access_log_clickhouse_addr"`
	// ftLBcUpmkQ.tUl2hoOYI0Ao.D4WJQARA; tag file offset 0x3188789
	AccessLogClickhouseAutoCreate bool `conf:"access_log_clickhouse_auto_create" default:"true" json:"access_log_clickhouse_auto_create"`
	// ftLBcUpmkQ.tUl2hoOYI0Ao.DOZx3XRAm01; tag file offset 0x318ac2f
	AccessLogClickhouseBatchSize int64 `conf:"access_log_clickhouse_batch_size" default:"1000" json:"access_log_clickhouse_batch_size"`
	// ftLBcUpmkQ.tUl2hoOYI0Ao.CmPnvU; tag file offset 0x3186309
	AccessLogClickhouseDatabase string `conf:"access_log_clickhouse_database" default:"default" json:"access_log_clickhouse_database"`
	// ftLBcUpmkQ.tUl2hoOYI0Ao.ACWNbHb1C; tag file offset 0x316d154
	AccessLogClickhousePassword string `conf:"access_log_clickhouse_password" json:"access_log_clickhouse_password"`
	// ftLBcUpmkQ.tUl2hoOYI0Ao.G8aycKMf5aa; tag file offset 0x318c390
	AccessLogClickhouseTable string `conf:"access_log_clickhouse_table" default:"access_log" json:"access_log_clickhouse_table"`
	// ftLBcUpmkQ.tUl2hoOYI0Ao.HnvQ_1vV; tag file offset 0x3180810
	AccessLogClickhouseUser string `conf:"access_log_clickhouse_user" default:"default" json:"access_log_clickhouse_user"`
	// ftLBcUpmkQ.tUl2hoOYI0Ao.INBdnGu56l5; tag file offset 0x318874a
	AccessLogDir string `conf:"access_log_dir" default:"/etc/soga/access_log" json:"access_log_dir"`
	// ftLBcUpmkQ.tUl2hoOYI0Ao.PmIFLM; tag file offset 0x316d120
	AccessLogEnable bool `conf:"access_log_enable" default:"false" json:"access_log_enable"`
	// ftLBcUpmkQ.tUl2hoOYI0Ao.WO1HZMaFg6Mx; tag file offset 0x3174bd6
	AccessLogMode string `conf:"access_log_mode" default:"local" json:"access_log_mode"`
	// ftLBcUpmkQ.tUl2hoOYI0Ao.EuOaOO8qBn0Y; tag file offset 0x317f7a2
	AccessLogRetentionHours int64 `conf:"access_log_retention_hours" default:"72" json:"access_log_retention_hours"`
	// ftLBcUpmkQ.siZtoGWL.BVi1B4f_v; tag file offset 0x315c598
	AnytlsFallbackAddr string `conf:"anytls_fallback_addr" json:"anytls_fallback_addr"`
	// ftLBcUpmkQ.siZtoGWL.JGw3yW; tag file offset 0x316b37f
	AnytlsFallbackPort int64 `conf:"anytls_fallback_port" default:"0" json:"anytls_fallback_port"`
	// ftLBcUpmkQ.i7BY8ClkrDX.NJSpG6; tag file offset 0x3157831
	Api string `conf:"api" default:"webapi" json:"api"`
	// ftLBcUpmkQ.watWxZSBeVv.Dh09He3a; tag file offset 0x3165f28
	AutoOutIp bool `conf:"auto_out_ip" default:"false" json:"auto_out_ip"`
	// ftLBcUpmkQ.watWxZSBeVv.F3BbbG_1qsA; tag file offset 0x316b3b4
	AutoUpdate bool `conf:"auto_update" default:"false" json:"auto_update"`
	// ftLBcUpmkQ.watWxZSBeVv.CVshaQaB33U; tag file offset 0x3171280
	BanPrivateIp bool `conf:"ban_private_ip" default:"false" json:"ban_private_ip"`
	// ftLBcUpmkQ.eFyNTD2_6X.BooNOdXcSa3U; tag file offset 0x3157813
	BlockListUrl string `conf:"block_list_url" json:"block_list_url"`
	// ftLBcUpmkQ.eFyNTD2_6X.U2hwBFC; tag file offset 0x315fb2b
	BlockListWhiteUserId []string `conf:"block_list_white_user_id" json:"block_list_white_user_id"`
	// ftLBcUpmkQ.cdqXEMYJO.Ga_YcC; tag file offset 0x3144f7f
	CertDomain string `conf:"cert_domain" json:"cert_domain"`
	// ftLBcUpmkQ.cdqXEMYJO.C2BNS6_QJC; tag file offset 0x314a5a6
	CertFile string `conf:"cert_file" json:"cert_file"`
	// ftLBcUpmkQ.cdqXEMYJO.AQ1zOwu1K; tag file offset 0x31540f3
	CertKeyLength string `conf:"cert_key_length" json:"cert_key_length"`
	// ftLBcUpmkQ.cdqXEMYJO.MVmP0dSlHl; tag file offset 0x31640bc
	CertMode string `conf:"cert_mode" default:"http" json:"cert_mode"`
	// ftLBcUpmkQ.watWxZSBeVv.Qxaw2_S; tag file offset 0x3164195
	CheckInterval int64 `conf:"check_interval" default:"60" json:"check_interval"`
	// ftLBcUpmkQ.x7sf3Tkb.Eb9vzdoE; tag file offset 0x316b3e1
	ConnLimitExpiry int64 `conf:"conn_limit_expiry" default:"60" json:"conn_limit_expiry"`
	// ftLBcUpmkQ.i7BY8ClkrDX.ApfXLZLmFXh; tag file offset 0x3147b30
	DbHost string `conf:"db_host" json:"db_host"`
	// ftLBcUpmkQ.i7BY8ClkrDX.MpUqmS0; tag file offset 0x315df7f
	DbMaxConn int64 `conf:"db_max_conn" default:"4" json:"db_max_conn"`
	// ftLBcUpmkQ.i7BY8ClkrDX.EUexnK81w_; tag file offset 0x316b2f3
	DbMaxIdleConn int64 `conf:"db_max_idle_conn" default:"4" json:"db_max_idle_conn"`
	// ftLBcUpmkQ.i7BY8ClkrDX.NawkeUTY_dJT; tag file offset 0x3172f98
	DbMaxIdleTime int64 `conf:"db_max_idle_time" default:"480" json:"db_max_idle_time"`
	// ftLBcUpmkQ.i7BY8ClkrDX.CsBHZVUxTO; tag file offset 0x3144f9e
	DbName string `conf:"db_name" json:"db_name"`
	// ftLBcUpmkQ.i7BY8ClkrDX.ASSy13OjR6aJ; tag file offset 0x31522ab
	DbPassword string `conf:"db_password" json:"db_password"`
	// ftLBcUpmkQ.i7BY8ClkrDX.Mk5cDiQzaj; tag file offset 0x3160f0d
	DbPort int64 `conf:"db_port" default:"3306" json:"db_port"`
	// ftLBcUpmkQ.i7BY8ClkrDX.ZGaSmv; tag file offset 0x315ac56
	DbUser string `conf:"db_user" default:"root" json:"db_user"`
	// ftLBcUpmkQ.uhg6MpMKJ.RHZA1kqpMSz; tag file offset 0x3150688
	DefaultDns []string `conf:"default_dns" json:"default_dns"`
	// ftLBcUpmkQ.watWxZSBeVv.XKO2Zot_hEk; tag file offset 0x316f30a
	DetectPacket bool `conf:"detect_packet" default:"false" json:"detect_packet"`
	// ftLBcUpmkQ.watWxZSBeVv.GozCogFPm; tag file offset 0x31780ad
	DetectPacketMaxLen int64 `conf:"detect_packet_max_len" default:"4096" json:"detect_packet_max_len"`
	// ftLBcUpmkQ.uhg6MpMKJ.PBvoBS2NX5; tag file offset 0x3169797
	DnsCacheTime int64 `conf:"dns_cache_time" default:"10" json:"dns_cache_time"`
	// ftLBcUpmkQ.uhg6MpMKJ.MFHBO42; tag file offset 0x314e9cd
	DnsConfigUrl string `conf:"dns_config_url" json:"dns_config_url"`
	// ftLBcUpmkQ.cdqXEMYJO.Xs7eJ3aj6Kbl; tag file offset 0x3154118
	DnsProvider string `conf:"dns_provider" json:"dns_provider"`
	// ftLBcUpmkQ.uhg6MpMKJ.EAOjNaQ6; tag file offset 0x3171217
	DnsStrategy string `conf:"dns_strategy" default:"ipv4_first" json:"dns_strategy"`
	// ftLBcUpmkQ.watWxZSBeVv.QgoKiaNp9; tag file offset 0x3178076
	DomainSniff []string `conf:"domain_sniff" default:"tls,http,quic" json:"domain_sniff"`
	// ftLBcUpmkQ.rXC9QSbKAoV0.CGGYGi0; tag file offset 0x315419b
	DyLimitDuration string `conf:"dy_limit_duration" json:"dy_limit_duration"`
	// ftLBcUpmkQ.rXC9QSbKAoV0.EFqkTZF6Wdql; tag file offset 0x3174ba1
	DyLimitEnable bool `conf:"dy_limit_enable" default:"false" json:"dy_limit_enable"`
	// ftLBcUpmkQ.rXC9QSbKAoV0.LxiE3fm4BLS; tag file offset 0x316b354
	DyLimitSpeed float64 `conf:"dy_limit_speed" default:"30" json:"dy_limit_speed"`
	// ftLBcUpmkQ.rXC9QSbKAoV0.Zao5joI9JY; tag file offset 0x3169768
	DyLimitTime int64 `conf:"dy_limit_time" default:"600" json:"dy_limit_time"`
	// ftLBcUpmkQ.rXC9QSbKAoV0.ILhRYq68NSUC; tag file offset 0x317c3bf
	DyLimitTriggerSpeed float64 `conf:"dy_limit_trigger_speed" default:"100" json:"dy_limit_trigger_speed"`
	// ftLBcUpmkQ.rXC9QSbKAoV0.PLAo2k09hxd; tag file offset 0x3178041
	DyLimitTriggerTime int64 `conf:"dy_limit_trigger_time" default:"60" json:"dy_limit_trigger_time"`
	// ftLBcUpmkQ.rXC9QSbKAoV0.IrsBkXPlx; tag file offset 0x315fb7f
	DyLimitWhiteUserId []string `conf:"dy_limit_white_user_id" json:"dy_limit_white_user_id"`
	// ftLBcUpmkQ.watWxZSBeVv.JGgVNMp; tag file offset 0x31767f9
	ForbiddenBitTorrent bool `conf:"forbidden_bit_torrent" default:"false" json:"forbidden_bit_torrent"`
	// ftLBcUpmkQ.watWxZSBeVv.DUpePpa39q; tag file offset 0x3155cb9
	ForbiddenPorts []string `conf:"forbidden_ports" json:"forbidden_ports"`
	// ftLBcUpmkQ.jkGZ0JHJw.CLr6mtlmQ; tag file offset 0x316f240
	ForceCloseSsl bool `conf:"force_close_ssl" default:"false" json:"force_close_ssl"`
	// ftLBcUpmkQ.watWxZSBeVv.YOBYD0m; tag file offset 0x3174c3b
	ForceProxyProtocol bool `conf:"force_proxy_protocol" default:"false" json:"force_proxy_protocol"`
	// ftLBcUpmkQ.xIoYVOH.SVuGy3CoRze; tag file offset 0x3174c74
	ForceVmessAead bool `conf:"force_vmess_aead" default:"false" json:"force_vmess_aead"`
	// ftLBcUpmkQ.watWxZSBeVv.YVMoJnAY; tag file offset 0x31db543
	GeoIpUrl string `conf:"geo_ip_url" default:"https://github.com/v2fly/geoip/releases/latest/download/geoip.dat" json:"geo_ip_url"`
	// ftLBcUpmkQ.watWxZSBeVv.YGrHEaVoNKL; tag file offset 0x31f88c7
	GeoSiteUrl string `conf:"geo_site_url" default:"https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat" json:"geo_site_url"`
	// ftLBcUpmkQ.watWxZSBeVv.JRQZn_; tag file offset 0x316d1b3
	GeoUpdateEnable bool `conf:"geo_update_enable" default:"false" json:"geo_update_enable"`
	// ftLBcUpmkQ.watWxZSBeVv.BIdU1vYs; tag file offset 0x316f36b
	GeoUpdateInterval int64 `conf:"geo_update_interval" default:"24" json:"geo_update_interval"`
	// ftLBcUpmkQ.cp9sUcOF.FpIPwenv; tag file offset 0x317f761
	IpUserCacheSaveDir string `conf:"ip_user_cache_save_dir" default:"/etc/soga/" json:"ip_user_cache_save_dir"`
	// ftLBcUpmkQ.cp9sUcOF.AROEPWNZd8SF; tag file offset 0x31807d6
	IpUserCacheSaveEnable bool `conf:"ip_user_cache_save_enable" default:"true" json:"ip_user_cache_save_enable"`
	// ftLBcUpmkQ.cp9sUcOF.TsRVDHP0SA; tag file offset 0x31711e6
	IpUserCacheTime int64 `conf:"ip_user_cache_time" default:"24" json:"ip_user_cache_time"`
	// ftLBcUpmkQ.cdqXEMYJO.JISdid54S5t; tag file offset 0x314a5c4
	KeyFile string `conf:"key_file" json:"key_file"`
	// ftLBcUpmkQ.aAGsqO.VerfnYj; tag file offset 0x3135fca
	Listen string `conf:"listen" json:"listen"`
	// ftLBcUpmkQ.zu_ScZG5P4.HSBWD7; tag file offset 0x316d215
	LogFileDir string `conf:"log_file_dir" default:"/etc/soga/" json:"log_file_dir"`
	// ftLBcUpmkQ.zu_ScZG5P4.G590aNjEOVK; tag file offset 0x3179a44
	LogFileRetentionDays int64 `conf:"log_file_retention_days" default:"7" json:"log_file_retention_days"`
	// ftLBcUpmkQ.zu_ScZG5P4.NaavbD4r35; tag file offset 0x31641f0
	LogLevel string `conf:"log_level" default:"info" json:"log_level"`
	// ftLBcUpmkQ.piJb6eaS.XpffP4ai; tag file offset 0x3178007
	MieruForceUserHint bool `conf:"mieru_force_user_hint" default:"false" json:"mieru_force_user_hint"`
	// ftLBcUpmkQ.aAGsqO.Arfg8UjxqP; tag file offset 0x315fb05
	Mptcp bool `conf:"mptcp" default:"false" json:"mptcp"`
	// ftLBcUpmkQ.juBqfxCScme.NXP6HvyFvmb9; tag file offset 0x3177fd4
	MuRegex string `conf:"mu_regex" default:"%5m%id.%suffix" json:"mu_regex"`
	// ftLBcUpmkQ.juBqfxCScme.DPqi4uoIl; tag file offset 0x3172ffd
	MuSuffix string `conf:"mu_suffix" default:"microsoft.com" json:"mu_suffix"`
	// ftLBcUpmkQ.i7BY8ClkrDX.N1Z81aDzg; tag file offset 0x315ac7f
	NodeId []string `conf:"node_id" default:"0" json:"node_id"`
	// ftLBcUpmkQ.watWxZSBeVv.QzlEP1r3t; tag file offset 0x31697f4
	NodeSpeedLimit float64 `conf:"node_speed_limit" default:"0" json:"node_speed_limit"`
	// ftLBcUpmkQ.qNDGFoxnh.OAHNXtGh; tag file offset 0x3147b65
	PprofAddr string `conf:"pprof_addr" json:"pprof_addr"`
	// ftLBcUpmkQ.qNDGFoxnh.PVSao2JIq; tag file offset 0x3169738
	PprofEnable bool `conf:"pprof_enable" default:"false" json:"pprof_enable"`
	// ftLBcUpmkQ.qNDGFoxnh.DXN_loYa; tag file offset 0x316416a
	PprofPort int64 `conf:"pprof_port" default:"21010" json:"pprof_port"`
	// ftLBcUpmkQ.a4aAMG.OAHNXtGh; tag file offset 0x3152286
	PrometheusAddr string `conf:"prometheus_addr" json:"prometheus_addr"`
	// ftLBcUpmkQ.a4aAMG.PVSao2JIq; tag file offset 0x3172f61
	PrometheusEnable bool `conf:"prometheus_enable" default:"false" json:"prometheus_enable"`
	// ftLBcUpmkQ.a4aAMG.DXN_loYa; tag file offset 0x316d0f1
	PrometheusPort int64 `conf:"prometheus_port" default:"19090" json:"prometheus_port"`
	// ftLBcUpmkQ.watWxZSBeVv.Osf81W0BWP; tag file offset 0x316f33b
	ProxyProtocol bool `conf:"proxy_protocol" default:"false" json:"proxy_protocol"`
	// ftLBcUpmkQ.watWxZSBeVv.KS63SD; tag file offset 0x316f2d3
	RandomIntervalRange int64 `conf:"random_interval_range" default:"10" json:"random_interval_range"`
	// ftLBcUpmkQ.x7sf3Tkb.Ij4bWLsuo_x4; tag file offset 0x31506a9
	RedisAddr string `conf:"redis_addr" json:"redis_addr"`
	// ftLBcUpmkQ.x7sf3Tkb.ZDYXh3Cuvxpw; tag file offset 0x3160f63
	RedisDb int64 `conf:"redis_db" default:"0" json:"redis_db"`
	// ftLBcUpmkQ.x7sf3Tkb.H2FCRVc; tag file offset 0x3165f54
	RedisEnable bool `conf:"redis_enable" default:"false" json:"redis_enable"`
	// ftLBcUpmkQ.vHzUrjrUZcY8.FXMKW6VcHH; tag file offset 0x315c5c0
	RedisIpLimitAddr string `conf:"redis_ip_limit_addr" json:"redis_ip_limit_addr"`
	// ftLBcUpmkQ.vHzUrjrUZcY8.ADewfG9Z64W; tag file offset 0x316f2a6
	RedisIpLimitDb int64 `conf:"redis_ip_limit_db" default:"0" json:"redis_ip_limit_db"`
	// ftLBcUpmkQ.vHzUrjrUZcY8.KCYNbwBsZ; tag file offset 0x3179962
	RedisIpLimitEnable bool `conf:"redis_ip_limit_enable" default:"false" json:"redis_ip_limit_enable"`
	// ftLBcUpmkQ.vHzUrjrUZcY8.BFkqcX7Dx; tag file offset 0x3174c08
	RedisIpLimitExpiry int64 `conf:"redis_ip_limit_expiry" default:"60" json:"redis_ip_limit_expiry"`
	// ftLBcUpmkQ.vHzUrjrUZcY8.AhScWSQ; tag file offset 0x315dfcf
	RedisIpLimitPassword string `conf:"redis_ip_limit_password" json:"redis_ip_limit_password"`
	// ftLBcUpmkQ.vHzUrjrUZcY8.NDRQGsmc132Y; tag file offset 0x317999d
	RedisIpLimitTls bool `conf:"redis_ip_limit_tls" default:"false" json:"redis_ip_limit_tls"`
	// ftLBcUpmkQ.x7sf3Tkb.A9GLBE4PY; tag file offset 0x31522ea
	RedisPassword string `conf:"redis_password" json:"redis_password"`
	// ftLBcUpmkQ.x7sf3Tkb.IDyeXiEv; tag file offset 0x3162705
	RedisTls bool `conf:"redis_tls" default:"false" json:"redis_tls"`
	// ftLBcUpmkQ.cEgBVJvq.M4qDq3KsUi; tag file offset 0x314c60f
	RoutesUrl string `conf:"routes_url" json:"routes_url"`
	// ftLBcUpmkQ.i7BY8ClkrDX.MnXMlyI; tag file offset 0x31640e5
	ServerType string `conf:"server_type" default:"v2ray" json:"server_type"`
	// ftLBcUpmkQ.watWxZSBeVv.Al5sHO4x90sY; tag file offset 0x3173068
	SniffRedirect bool `conf:"sniff_redirect" default:"false" json:"sniff_redirect"`
	// ftLBcUpmkQ.o9NA6hjqxImy.RM5SFRF; tag file offset 0x313e8c6
	SogaKey string `conf:"soga_key" json:"soga_key"`
	// ftLBcUpmkQ.avoYN3oP9N4.TzpbaXGDeaz; tag file offset 0x3155c97
	SogaPanelKey string `conf:"soga_panel_key" json:"soga_panel_key"`
	// ftLBcUpmkQ.avoYN3oP9N4.ZkkjP9; tag file offset 0x314c5ed
	SogaPanelUrl string `conf:"soga_panel_url" json:"soga_panel_url"`
	// ftLBcUpmkQ.vW8lXY.UA4PZU; tag file offset 0x317302e
	SsInvalidAccessCount int64 `conf:"ss_invalid_access_count" default:"30" json:"ss_invalid_access_count"`
	// ftLBcUpmkQ.vW8lXY.PWFghdU; tag file offset 0x31799d0
	SsInvalidAccessDuration int64 `conf:"ss_invalid_access_duration" default:"60" json:"ss_invalid_access_duration"`
	// ftLBcUpmkQ.vW8lXY.X4_AmA8j7; tag file offset 0x317d480
	SsInvalidAccessEnable bool `conf:"ss_invalid_access_enable" default:"false" json:"ss_invalid_access_enable"`
	// ftLBcUpmkQ.vW8lXY.SndqWD26h; tag file offset 0x318780c
	SsInvalidAccessForbiddenTime int64 `conf:"ss_invalid_access_forbidden_time" default:"600" json:"ss_invalid_access_forbidden_time"`
	// ftLBcUpmkQ.paRsja6.DlaO1l; tag file offset 0x316784a
	SsObfsMode string `conf:"ss_obfs_mode" default:"relaxed" json:"ss_obfs_mode"`
	// ftLBcUpmkQ.juBqfxCScme.XHTMQfO; tag file offset 0x3164111
	SsObfsUdp bool `conf:"ss_obfs_udp" default:"false" json:"ss_obfs_udp"`
	// ftLBcUpmkQ.juBqfxCScme.NLpXVVM0x; tag file offset 0x31696da
	SsrCidLimit bool `conf:"ssr_cid_limit" default:"true" json:"ssr_cid_limit"`
	// ftLBcUpmkQ.i7BY8ClkrDX.AG_mSFklcvj; tag file offset 0x314a5e1
	SubType string `conf:"sub_type" json:"sub_type"`
	// ftLBcUpmkQ.watWxZSBeVv.KI4eIM8J; tag file offset 0x317afea
	SubmitAliveIpMinTraffic float64 `conf:"submit_alive_ip_min_traffic" default:"0" json:"submit_alive_ip_min_traffic"`
	// ftLBcUpmkQ.watWxZSBeVv.Fak_7LgVV; tag file offset 0x31697c5
	SubmitInterval int64 `conf:"submit_interval" default:"60" json:"submit_interval"`
	// ftLBcUpmkQ.watWxZSBeVv.QiLulXrJUA0; tag file offset 0x317124d
	SubmitRealIp bool `conf:"submit_real_ip" default:"false" json:"submit_real_ip"`
	// ftLBcUpmkQ.watWxZSBeVv.DhXdMvN; tag file offset 0x31780e2
	SubmitTrafficMinTraffic float64 `conf:"submit_traffic_min_traffic" default:"0" json:"submit_traffic_min_traffic"`
	// ftLBcUpmkQ.aAGsqO.Hni9vNgOp4g; tag file offset 0x3167821
	TcpTimeout int64 `conf:"tcp_timeout" default:"120" json:"tcp_timeout"`
	// ftLBcUpmkQ.aAGsqO.Fg5sk_; tag file offset 0x3155c6f
	Tfo bool `conf:"tfo" default:"false" json:"tfo"`
	// ftLBcUpmkQ.jkGZ0JHJw.RS1kBzpBezso; tag file offset 0x3172fcc
	TlsAlpn []string `conf:"tls_alpn" default:"h2,http/1.1" json:"tls_alpn"`
	// ftLBcUpmkQ.jkGZ0JHJw.KVniDErTtx; tag file offset 0x3159411
	TlsCipherSuites string `conf:"tls_cipher_suites" json:"tls_cipher_suites"`
	// ftLBcUpmkQ.jkGZ0JHJw.NH7oB3o7; tag file offset 0x31522c8
	TlsMaxVersion string `conf:"tls_max_version" json:"tls_max_version"`
	// ftLBcUpmkQ.jkGZ0JHJw.CJri5kB26; tag file offset 0x3154137
	TlsMinVersion string `conf:"tls_min_version" json:"tls_min_version"`
	// ftLBcUpmkQ.jkGZ0JHJw.JOyIs3s9WAcA; tag file offset 0x318abec
	TlsPreferServerCipherSuites bool `conf:"tls_prefer_server_cipher_suites" default:"true" json:"tls_prefer_server_cipher_suites"`
	// ftLBcUpmkQ.bKCIPg.BYiTyYPg3; tag file offset 0x31593eb
	TrojanRemoteAddr string `conf:"trojan_remote_addr" json:"trojan_remote_addr"`
	// ftLBcUpmkQ.bKCIPg.EglOu0OdYex; tag file offset 0x31711b4
	TrojanRemotePort int64 `conf:"trojan_remote_port" default:"0" json:"trojan_remote_port"`
	// ftLBcUpmkQ.k_lu9bPK.JHXrVGNjg31; tag file offset 0x316f274
	TunnelEnable bool `conf:"tunnel_enable" default:"false" json:"tunnel_enable"`
	// ftLBcUpmkQ.k_lu9bPK.ZjL7PiTY; tag file offset 0x3174b68
	TunnelMethod string `conf:"tunnel_method" default:"aes-128-gcm" json:"tunnel_method"`
	// ftLBcUpmkQ.k_lu9bPK.RtHB6a; tag file offset 0x3160f33
	TunnelMux bool `conf:"tunnel_mux" default:"false" json:"tunnel_mux"`
	// ftLBcUpmkQ.k_lu9bPK.D38NXN3uV; tag file offset 0x3154159
	TunnelPassword string `conf:"tunnel_password" json:"tunnel_password"`
	// ftLBcUpmkQ.k_lu9bPK.GbyJkc; tag file offset 0x3169706
	TunnelType string `conf:"tunnel_type" default:"ws-tunnel" json:"tunnel_type"`
	// ftLBcUpmkQ.k_lu9bPK.LYSz_mSWFTQp; tag file offset 0x316b325
	TunnelWsPath string `conf:"tunnel_ws_path" default:"/" json:"tunnel_ws_path"`
	// ftLBcUpmkQ.i7BY8ClkrDX.EtRWBSEhLQc; tag file offset 0x31696ad
	Type string `conf:"type" default:"sspanel-uim" json:"type"`
	// ftLBcUpmkQ.watWxZSBeVv.UeBhd4nohvCF; tag file offset 0x3179a0d
	UdpProxyProtocol bool `conf:"udp_proxy_protocol" default:"false" json:"udp_proxy_protocol"`
	// ftLBcUpmkQ.aAGsqO.JtFIOYSoCNi; tag file offset 0x3164091
	UdpTimeout int64 `conf:"udp_timeout" default:"2" json:"udp_timeout"`
	// ftLBcUpmkQ.watWxZSBeVv.ItKGl9keQrlY; tag file offset 0x316d188
	UserConnLimit int64 `conf:"user_conn_limit" default:"0" json:"user_conn_limit"`
	// ftLBcUpmkQ.watWxZSBeVv.JQC3mlZzpS69; tag file offset 0x31817d2
	UserIpLimitCidrPrefixV4 int64 `conf:"user_ip_limit_cidr_prefix_v4" default:"32" json:"user_ip_limit_cidr_prefix_v4"`
	// ftLBcUpmkQ.watWxZSBeVv.BkelkzTWy; tag file offset 0x317f7dc
	UserIpLimitCidrPrefixV6 int64 `conf:"user_ip_limit_cidr_prefix_v6" default:"128" json:"user_ip_limit_cidr_prefix_v6"`
	// ftLBcUpmkQ.watWxZSBeVv.YyLGOC; tag file offset 0x31641c0
	UserSpeedLimit float64 `conf:"user_speed_limit" default:"0" json:"user_speed_limit"`
	// ftLBcUpmkQ.watWxZSBeVv.P6KMmld; tag file offset 0x31626d9
	UserTcpLimit int64 `conf:"user_tcp_limit" default:"0" json:"user_tcp_limit"`
	// ftLBcUpmkQ.xIoYVOH.GnOeZP5RIl; tag file offset 0x315c5e7
	V2rayFallbackAddr string `conf:"v2ray_fallback_addr" json:"v2ray_fallback_addr"`
	// ftLBcUpmkQ.xIoYVOH.HUt3s7n_8; tag file offset 0x316f39e
	V2rayFallbackPort int64 `conf:"v2ray_fallback_port" default:"0" json:"v2ray_fallback_port"`
	// ftLBcUpmkQ.xIoYVOH.SElnoFh_fIwr; tag file offset 0x317b027
	V2rayReduceMemory bool `conf:"v2ray_reduce_memory" default:"false" json:"v2ray_reduce_memory"`
	// ftLBcUpmkQ.vW8lXY.Zdj5DFrb4WqO; tag file offset 0x31887cf
	VmessAeadInvalidAccessCount int64 `conf:"vmess_aead_invalid_access_count" default:"30" json:"vmess_aead_invalid_access_count"`
	// ftLBcUpmkQ.vW8lXY.BPUCSK_mS81; tag file offset 0x318ac73
	VmessAeadInvalidAccessDuration int64 `conf:"vmess_aead_invalid_access_duration" default:"60" json:"vmess_aead_invalid_access_duration"`
	// ftLBcUpmkQ.vW8lXY.H1kZa6; tag file offset 0x3186349
	VmessAeadInvalidAccessEnable bool `conf:"vmess_aead_invalid_access_enable" default:"false" json:"vmess_aead_invalid_access_enable"`
	// ftLBcUpmkQ.vW8lXY.ITmtDnIa8J; tag file offset 0x319ac07
	VmessAeadInvalidAccessForbiddenTime int64 `conf:"vmess_aead_invalid_access_forbidden_time" default:"600" json:"vmess_aead_invalid_access_forbidden_time"`
	// ftLBcUpmkQ.xIoYVOH.ZFK_OBT1; tag file offset 0x316b411
	VmessAuthMode string `conf:"vmess_auth_mode" default:"auto" json:"vmess_auth_mode"`
	// ftLBcUpmkQ.xIoYVOH.RIFsRvm1; tag file offset 0x3159434
	VmessFallbackAddr string `conf:"vmess_fallback_addr" json:"vmess_fallback_addr"`
	// ftLBcUpmkQ.xIoYVOH.YMm_xn_v; tag file offset 0x316d1e6
	VmessFallbackPort int64 `conf:"vmess_fallback_port" default:"0" json:"vmess_fallback_port"`
	// ftLBcUpmkQ.xIoYVOH.Ff3xSe; tag file offset 0x31712ae
	VmessReduceMemory bool `conf:"vmess_reduce_memory" default:"false" json:"vmess_reduce_memory"`
	// ftLBcUpmkQ.i7BY8ClkrDX.UnkaBGBuOUXV; tag file offset 0x3150669
	WebapiKey string `conf:"webapi_key" json:"webapi_key"`
	// ftLBcUpmkQ.i7BY8ClkrDX.MKrU9XEJ; tag file offset 0x314c62b
	WebapiMukey string `conf:"webapi_mukey" json:"webapi_mukey"`
	// ftLBcUpmkQ.i7BY8ClkrDX.VfiX6TsWZxF; tag file offset 0x314e993
	WebapiUrl string `conf:"webapi_url" json:"webapi_url"`
	// ftLBcUpmkQ.pkfwYwZ1aHu.M4qDq3KsUi; tag file offset 0x315417c
	WhiteListUrl string `conf:"white_list_url" json:"white_list_url"`
	// ftLBcUpmkQ.pKGHLtJsa.W2WFtBWP; tag file offset 0x316413e
	WhmcsAlterId int64 `conf:"whmcs_alter_id" default:"2" json:"whmcs_alter_id"`
	// ftLBcUpmkQ.pKGHLtJsa.Et04j58qH; tag file offset 0x314e9b0
	WhmcsMethod string `conf:"whmcs_method" json:"whmcs_method"`
	// ftLBcUpmkQ.pKGHLtJsa.X4Dd6nOZ_7; tag file offset 0x3162686
	WhmcsNet string `conf:"whmcs_net" default:"tcp" json:"whmcs_net"`
	// ftLBcUpmkQ.pKGHLtJsa.HmKQa3xt; tag file offset 0x3147b49
	WhmcsObfs string `conf:"whmcs_obfs" json:"whmcs_obfs"`
	// ftLBcUpmkQ.pKGHLtJsa.Z9bFboOQlPiw; tag file offset 0x315787f
	WhmcsPassword string `conf:"whmcs_password" json:"whmcs_password"`
	// ftLBcUpmkQ.pKGHLtJsa.VD6q_75hbej2; tag file offset 0x3165ed2
	WhmcsPort int64 `conf:"whmcs_port" default:"80" json:"whmcs_port"`
	// ftLBcUpmkQ.pKGHLtJsa.EKv8Zjg7dn85; tag file offset 0x31578a3
	WhmcsProtocol string `conf:"whmcs_protocol" json:"whmcs_protocol"`
	// ftLBcUpmkQ.pKGHLtJsa.IlqtsyWu; tag file offset 0x315dfa8
	WhmcsRate float64 `conf:"whmcs_rate" default:"1" json:"whmcs_rate"`
	// ftLBcUpmkQ.pKGHLtJsa.Ew45bIap; tag file offset 0x3157857
	WhmcsServiceName string `conf:"whmcs_service_name" json:"whmcs_service_name"`
	// ftLBcUpmkQ.pKGHLtJsa.Dd5Xza; tag file offset 0x315fb53
	WhmcsTls bool `conf:"whmcs_tls" default:"false" json:"whmcs_tls"`
	// ftLBcUpmkQ.pKGHLtJsa.NQ3CpRlonU; tag file offset 0x3165efd
	WhmcsWsPath string `conf:"whmcs_ws_path" default:"/" json:"whmcs_ws_path"`
}
