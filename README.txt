soga-reconstructed — 独立兼容实现与源码工程
参考样本：soga 2.17.0，Linux amd64

GitHub 下载与一键安装：见根目录 GITHUB.txt。
构建产物：https://github.com/Miku-programm/soga-v1/releases/latest
面板通讯密钥填 webapi_key；soga_key 和 soga_panel_* 留空。
本次上传按用户要求保留现有 v2node 行为，已知接口路径差异没有修复。

这个工程能从源码构建并运行代理服务。它依据提供的文档、原程序的 Go
类型信息和静态反编译证据重新实现业务逻辑，协议底层使用注明来源的
开源实现。它不是原作者遗失源码的逐字恢复，也不声称与原二进制逐字节相同。
原始样本没有运行、没有修改；原程序的授权服务没有被修改或绕过。

工程内容

• proxy：VMess、VLESS、Trojan、Shadowsocks、SSR、AnyTLS、Hysteria 1/2、Mieru；
  TCP/UDP、WS/HTTP/gRPC、VLESS Reality/Vision/XHTTP/MLKEM、回落、来源识别。
• panel：soga-v1、V2Board、Xboard、PPANEL、ProxyPanel、SSPanel-uim、WHMCS、
  V2RaySocks、XiaoV2Board（含 v2node）、DJ；SSPanel/WHMCS MySQL 适配器。
  每种面板实际支持的协议和上报能力不同，见 panel/ 与验收清单。
• engine：拉取节点和用户、监听端口装配、多用户/多端口、更新失败回滚、
  流量与在线 IP 上报、面板规则、访问日志、主机状态和动态限速。
• resolver/routing/policy：可配置 DNS、DoT/DoH、规则路由、代理出站、
  GeoIP/GeoSite、域名嗅探、黑白名单和首包检查。
• certificates：已有证书、自签证书、面板内联证书、acme.sh HTTP/DNS 签发。
• redislimit：真实 Redis 原子配额与租约；monitor：指标与独立 pprof 服务。
• accounting：持久化待上报流量；updater：独立发行清单与哈希验证更新。
• tunnel：TCP、TLS、WebSocket、WebSocket+TLS 隧道，AEAD、smux、
  TCP/UDP 载荷及来源信息；同时保留业务层 TLS 与传输配置。
• config/rulelist/service：保存先前从原程序恢复的配置、名单和调度行为。

快速使用（Linux）

1. 阅读 examples/部署说明.txt，并修改 examples/soga.conf 中的虚构面板地址、
   API key、协议和节点 ID。新工程的名称和安装目录为 soga-reconstructed。
2. 前台启动：
     ./bin/soga-reconstructed-linux-amd64 serve -c examples/soga.conf \
       -b examples/blockList -w examples/whiteList -d examples/dns.yml \
       -r examples/routes.toml -state-dir ./state
   不存在的可选规则文件按空配置处理；state、证书及缓存目录必须可写。
   配置文件同目录的 geosite.dat / geoip.dat 会自动加载；显式命令参数优先。
   日志与认证缓存目录由配置里的 log_file_dir、ip_user_cache_save_dir 控制。
3. 安装 systemd 模板：
     sudo scripts/install.sh
     sudo soga-reconstructed instance config default webapi_url=https://YOUR-PANEL webapi_key=YOUR-KEY node_id=1
     sudo soga-reconstructed instance start default
   安装保留既有配置，默认不启动、不启用服务。
4. 建立另一实例：
     sudo soga-reconstructed instance new node2 node_id=2
     sudo soga-reconstructed instance start node2
   一个配置内 node_id=1,2 也可以运行多个节点。
5. 停止时会关闭监听并尝试最后一次流量上报；失败的数据保留在 state 内。

构建和验证

本次开发使用 Go 1.27.3。发行包内的 vendor/ 固定依赖版本，构建不需要
访问模块仓库。third_party/xray-core 保存带并发修复的 MPL-2.0 源码副本，
third_party/sing-box 保存显式旧 TLS 套件兼容修改及 GPL-3.0 源码。

  CGO_ENABLED=0 go test -mod=vendor ./...
  scripts/build.sh all
  python3 scripts/smoke.py bin/soga-reconstructed-linux-amd64

scripts/build.sh 生成 Linux amd64、arm64 程序及 SHA256SUMS。可用 GO 指定
Go 路径。macOS/Windows 不是本次运行时验收目标。独立 Redis、SSR Python
客户端及数据库测试需要测试工具；缺失时显示 SKIP，不能把它当成通过。
实际执行的命令、日志、哈希和通过/失败情况记录在随包 validation/ 中。
完整复现步骤见 validation/验证复现说明.txt。

行为边界

1. 协议连接在本机真实客户端上验收；面板 HTTP 测试使用合成 fixture。
   没有你的生产面板、实际账号、域名或 DNS 凭据，因此未声称已完成你的
   生产部署。ACME 使用真实 acme.sh，自动化验收不签发真实公共证书。
2. 监听配置和用户更新会重建受影响的监听器，已有连接可能中断。
   验证失败保持旧配置；重绑失败会尝试恢复旧监听。
3. 流量上报采取持久化后重试。服务器已接受但应答丢失时可能重复计费；
   面板 API 没有统一幂等键，不能承诺 exactly-once。进程崩溃前尚未采样的
   少量流量也可能丢失。审计、在线与认证缓存不等于持久化账本。
4. Redis 的 key 格式为本重建工程定义。可以在本工程多个实例间共享限制，
   不能与原版 soga 混用同一配额计数。Redis 不可达时保留本机限制并记录错误。
5. 限速采用十进制 Mbps、上下行合计、64 KiB 突发；其算法为独立实现。
   CIDR、在线过期、动态限速与访问规则的具体重建语义见源码和测试。
6. SSR 混淆单端口的普通用户由 Host/SNI 识别，承载账号提供外层密钥。
   该模式 UDP 默认关闭；显式开启后无法归属普通用户，因此不计入普通用户
   流量、在线或用户配额，仍受节点限速和访问规则约束。
7. 本地 DNS 规则先匹配，随后面板 DNS 规则，最后默认 DNS/系统解析器。
   路由健康检查验证 TCP 可达性，不代表代理认证或最终目的站可达。
   新运行时对远程名单要求 HTTP 200、10 秒超时和 8 MiB 上限；拉取失败
   保持已安装规则。forbidden_ports 在缺少本地名单或使用远程名单时也生效。
   这些是运行时明确的改进；rulelist 包仍保留恢复出的原加载行为供对照。
8. auto_update 使用本工程自己的 HTTPS 发行清单。没有默认托管发行源；
   开启时必须给 -update-manifest 或 reconstruction_update_url。
   绝不从原版 soga 的更新地址替换为原程序。更新后需重启进程或容器。
9. tls_prefer_server_cipher_suites 在现代 Go 中已废弃，TLS 套件优先级由
   Go 运行时决定；TLS 1.3 的套件选择同样由 Go 控制，显式配置套件影响
   TLS 1.2 及更早版本。冒号分隔的套件名及十六进制 ID 均支持。
   pass 隧道采用从本样本静态恢复的独立兼容实现；TCP/TLS/WS/WS-TLS
   外层保留业务协议的内层 TLS 和传输层。隧道外层 TLS 单独读取 cert_*
   配置并持久化证书；不会复用面板下发的内层证书。支持的类型为
   tcp-tunnel、tls-tunnel、ws-tunnel、ws-tls-tunnel，亦可省略 -tunnel。
   Mieru 隧道按文档使用 TCP 底层，可承载 TCP/UDP 业务；Hysteria 未发现
   同样的隧道调用链。quic-tunnel 元数据分支与实际 TCP 调用链不一致，
   尚无可验证的 QUIC 线协议，这些组合会明确拒绝。
10. soga_key 是原产品商业授权配置；本独立工程不调用原授权服务器，
    也不复制其商业授权逻辑。soga_panel_url/key 是另外的配置服务字段，
    不能归为授权字段。样本中已确认“soga panel mode”日志，但自动上报/
    加载的 HTTP 契约尚未取得；官方公开文档站本次核对返回 401 认证要求。
    设置任一 soga_panel_* 字段会在启动前明确报错。请清空这两个字段，
    直接设置 type/api/webapi_url/webapi_key/node_id；不会猜测服务端点。
11. 部分现代面板扩展字段或协议组合没有足够证据；遇到已识别但未映射的
    行为会明确拒绝该配置。不能把“解析了配置字段”理解为全部功能已恢复。

源码与许可

本工程新代码以 GPL-3.0 发布。第三方各自的许可证、版权通知保留在源码、
vendor、certificates/bundled、geodata、proxy/internal、proxy/ssrcore 和
third_party 中；GeoIP/GeoSite 数据另有署名及共享要求。THIRD_PARTY_NOTICES.txt
列出关键来源；模块版本以 go.mod、go.sum、vendor/modules.txt 为准。
静态反编译证据与独立重建源码分别保存，避免把新写的实现误称原始源码。
