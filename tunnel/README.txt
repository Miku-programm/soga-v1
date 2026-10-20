pass 隧道恢复说明

本目录记录针对所附 soga 2.17.0 文件的静态证据；未执行原文件。tunnel 包为独立编写的兼容实现，不是原始 Go 源码。详细地址、公式、分层和限制见 wire-evidence.json。

已实现 TCP、TLS、WebSocket、WebSocket+TLS，四种 AEAD、smux v1/v2、TCP 流和 UDP 报文。外层配置的 PROXY 头与隧道内部可选来源头是两层独立功能；业务 TLS/Reality/WS/H2/gRPC/XHTTP 仍位于隧道内，没有因启用隧道删除业务层。SS/SSR 的 UDP 内容保留完整原协议加密报文，由原协议适配器继续验证。

验证包含独立 Python 加密实现、官方 smux/WebSocket 库、真实 VMess/VLESS/Trojan/AnyTLS/SS/SSR 客户端及目标套接字。边界测试包括回放、篡改、截断、短读、65535 字节、多个 mux 流和并发关闭。Mieru 官方 SDK 的 TCP 底层隧道适配与测试由主任务记录。未获得并执行官方 pass 客户端，因此不声称所有 pass 发行版本均已互通。

QUIC 配置名虽然出现在原工厂，已恢复的 soga 监听路径却固定创建 TCP，且 IsQuic 分支直接返回它。没有足够证据构建 QUIC/ALPN 传输，当前明确拒绝此类型。Hysteria 未发现该隧道监听器调用；Mieru 原文档只要求 TCP 底层，新增原生 UDP 底层与隧道组合也不作推测。

重建额外采用：完整长度读写、认证失败后固定错误、10 秒握手限时、并行握手、10 分钟/65536 项已认证 nonce 回放缓存；这些策略有明确边界，不冒称恢复了原版所有实现细节。
