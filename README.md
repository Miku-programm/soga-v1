# soga-v1

基于 soga 2.17.0 文档和静态分析证据的独立兼容实现，提供 Linux amd64、arm64 程序、完整源码和交互式管理菜单。本工程不是原作者源码的逐字恢复，也不保证与原程序所有行为一致。

[下载最新版](https://github.com/Miku-programm/soga-v1/releases/latest) · [构建记录](https://github.com/Miku-programm/soga-v1/actions) · [安装与管理说明](GITHUB.md) · [实现与兼容性说明](docs/COMPATIBILITY.md)

## 一键安装

在支持 systemd 的 Linux 服务器上，以 **root** 执行：

```bash
bash <(curl -Ls https://raw.githubusercontent.com/Miku-programm/soga-v1/main/install.sh)
```

安装脚本会识别架构、安装依赖和证书工具、校验下载包并安装服务。交互式安装结束后自动打开菜单，也可随时运行：

```bash
soga
```

首次安装使用下方的默认配置模板，需要填写实际面板地址、通讯密钥、协议和节点 ID 后启动。重新安装会保留已有配置；它不会用新模板覆盖现有的 `soga.conf`。

## 更新

更新管理菜单后，重新打开菜单：

```bash
soga self-update
soga
```

更新程序并保留已有配置：

```bash
soga update
```

更新程序会重启默认实例；其他运行中的实例可在各自菜单中重启。主菜单可切换稳定版或测试版；测试版使用 GitHub 预发布，没有预发布时会明确提示。

## 配置文件

默认模板位于 [`examples/soga.conf`](examples/soga.conf)，按提供的原版模板设置参数值，说明注释使用中文。

| 项目 | 路径或名称 |
| --- | --- |
| 默认实例配置 | `/etc/soga/soga.conf` |
| 其他实例配置 | `/etc/soga/实例名/soga.conf` |
| 主程序 | `/usr/local/soga/soga` |
| 管理命令 | `/usr/bin/soga` |
| 默认实例服务 | `soga.service` |
| 其他实例服务 | `soga@实例名.service` |
| 原安装文件备份 | `/var/backups/soga/` |

`/usr/local/bin/soga` 是兼容入口，用于兼容旧终端缓存的命令路径。

### 默认配置

```ini
# 基础配置
type=xiaov2board
server_type=
node_id=

# 接口对接或数据库对接任选一种
api=webapi

# 接口对接信息
webapi_url=
webapi_key=

# 数据库对接信息
db_host=
db_port=
db_name=
db_user=
db_password=

# 手动证书配置
cert_file=
key_file=

# 自动证书配置
cert_mode=
cert_domain=
cert_key_length=ec-256
dns_provider=

# 代理协议中转配置
proxy_protocol=true
udp_proxy_protocol=true
# 可信中转地址（IP 或 CIDR，逗号分隔），只采用这些地址发来的代理协议头；
# 留空则信任任何来源，客户端可伪造来源 IP 绕过 IP 限制，建议填写中转服务器地址
proxy_protocol_trusted=

# 全局用户连接地址数量限制配置（需要 Redis 8.0 或更高版本）
redis_ip_limit_enable=false
redis_ip_limit_addr=
redis_ip_limit_password=
redis_ip_limit_db=0
redis_ip_limit_tls=false
redis_ip_limit_expiry=60

# 动态限速配置
dy_limit_enable=true
dy_limit_duration=20:00-24:00,00:00-06:00
dy_limit_trigger_time=180
dy_limit_trigger_speed=100
dy_limit_speed=50
dy_limit_time=600
dy_limit_white_user_id=1,107,8740,8443,442

# 其他限制配置
user_conn_limit=0
user_speed_limit=0
user_tcp_limit=0
node_speed_limit=0

# 同步间隔与日志配置
check_interval=60
submit_interval=60
forbidden_bit_torrent=true
log_level=warn
access_log_enable=true
access_log_dir=/etc/soga/access_log
access_log_retention_hours=72

# 在线地址上报的最低流量要求
submit_alive_ip_min_traffic=300

# 更多配置项请参阅文档，按需添加
```

### 填写说明

- `type` 默认是 `xiaov2board`；`server_type`、`node_id`、`webapi_url` 和 `webapi_key` 按实际面板节点填写。
- `webapi_key` 是面板后端通讯密钥，不是 GitHub 密钥。V2Board 类面板通常在后台节点设置中配置该值。
- `api=webapi` 使用接口对接；数据库对接需改为 `api=db`，填写数据库信息，并确认对应面板适配器支持数据库模式。
- 模板保留了 `proxy_protocol=true` 和 `udp_proxy_protocol=true`，上游应发送匹配的代理协议头；客户端直接连接时应按部署情况调整这两项。
- `proxy_protocol_trusted` 填中转服务器的 IP 或网段（逗号分隔）。填写后只采用这些地址发来的代理协议头，其他来源一律按真实地址处理；同时开启 `force_proxy_protocol=true` 时，非中转来源的连接会被拒绝。留空会信任任何来源，客户端可以伪造来源 IP 绕过 IP 数限制，启动日志会给出警告。
- 动态限速时段、阈值和白名单均按提供的模板保留，可按实际需求修改。
- 本工程不调用原版商业授权服务，`soga_key` 可留空；尚未恢复的 `soga_panel_url`、`soga_panel_key` 均应留空。

> 已知兼容性限制：现有 `v2node` 接口路径差异仍保留。更换默认模板不代表该接口兼容性已经修复。

## 实例管理

主菜单支持安装更新、卸载、切换分支、更新管理脚本、新增实例以及进入实例菜单。

实例二级菜单：

```text
  0. 返回上级
————————————————
  1. 启动
  2. 停止
  3. 重启
  4. 重载配置
————————————————
  5. 查看服务状态详情
  6. 查看最近日志 (1000行)
  7. 持续输出日志
————————————————
  8. 设置开机自启
  9. 取消开机自启
————————————————
 10. 快速配置 soga.conf
 11. 编辑 soga.conf
 12. 编辑 blockList
 13. 编辑 whiteList
 14. 编辑 routes.toml
 15. 编辑 dns.yml
```

重载会刷新面板数据和规则文件；修改 `soga.conf` 后需要重启。快速配置和主配置编辑完成后会提供重启选项。

常用命令：

```bash
soga list
soga new anytls server_type=anytls node_id=2
soga config anytls
soga start anytls
soga enable anytls
soga log anytls -f
soga restart anytls
```

新增实例默认不启动，需确认节点配置、证书及端口后启动。重命名和删除可使用 `soga rename`、`soga remove`；默认实例不能重命名或删除。

## 卸载

```bash
soga uninstall
```

输入 `y` 或 `Y` 确认后，停止并卸载程序，删除 `/etc/soga` 中的配置。原安装备份保留在 `/var/backups/soga`。直接执行安装包中的 `scripts/uninstall.sh` 会保留配置。

## 功能范围

- proxy：VMess、VLESS、Trojan、Shadowsocks、SSR、AnyTLS、Hysteria 1/2、Mieru；
  TCP/UDP、WS/HTTP/gRPC、VLESS Reality/Vision/XHTTP/MLKEM、回落、来源识别。
- panel：soga-v1、V2Board、Xboard、PPANEL、ProxyPanel、SSPanel-uim、WHMCS、
  V2RaySocks、XiaoV2Board（含 v2node）、DJ；SSPanel/WHMCS MySQL 适配器。
  每种面板实际支持的协议和上报能力不同，见 panel/ 与验收清单。
- engine：拉取节点和用户、监听端口装配、多用户/多端口、更新失败回滚、
  流量与在线 IP 上报、面板规则、访问日志、主机状态和动态限速。
- resolver/routing/policy：可配置 DNS、DoT/DoH、规则路由、代理出站、
  GeoIP/GeoSite、域名嗅探、黑白名单和首包检查。
- certificates：已有证书、自签证书、面板内联证书、acme.sh HTTP/DNS 签发。
- redislimit：真实 Redis 原子配额与租约；monitor：指标与独立 pprof 服务。
- accounting：持久化待上报流量；updater：独立发行清单与哈希验证更新。
- tunnel：TCP、TLS、WebSocket、WebSocket+TLS 隧道，AEAD、smux、
  TCP/UDP 载荷及来源信息；同时保留业务层 TLS 与传输配置。
- config/rulelist/service：保存先前从原程序恢复的配置、名单和调度行为。

## 从源码构建

构建使用 Go 1.27.3，依赖固定在 `vendor/` 中。以下命令在源码目录执行：

```bash
sh scripts/build.sh all
```

构建产物位于 `bin/`。检查命令：

```bash
CGO_ENABLED=0 go vet -mod=vendor ./...
CGO_ENABLED=0 go test -mod=vendor ./...
python3 scripts/smoke.py bin/soga-reconstructed-linux-amd64
python3 scripts/runtime_smoke.py bin/soga-reconstructed-linux-amd64
python3 -m unittest discover -s scripts -p 'test_*.py' -v
```

推送任意分支或提交 PR，GitHub Actions 都会执行 `go vet`、Go 单元测试、构建和检查；只有 `main` 会发布 Release（程序、安装包、源码、检查记录和 `SHA256SUMS`）。推送 `main` 只生成测试版（预发布）；确认无误后，在 Actions 手动运行并选择 `stable`，才会发布一键安装和 `soga update` 默认使用的稳定版：

```bash
gh workflow run build.yml -f channel=stable
```

amd64 执行命令行、本地进程、管理菜单和安装流程检查；arm64 为交叉编译。每次发布不重复历史完整集成测试。`validation/` 保存历史验收记录；生产面板和真实账号的连接能力需在实际部署中验证。

## 兼容性与许可

自动配置服务和 QUIC 隧道等未恢复功能、流量上报边界及其他兼容性差异详见 [实现与兼容性说明](docs/COMPATIBILITY.md)。

新代码以 [GPL-3.0](LICENSE) 发布。第三方代码与数据的许可和署名见 [第三方来源说明](THIRD_PARTY_NOTICES.txt) 和 `LICENSES/`；依赖版本以 `go.mod`、`go.sum`、`vendor/modules.txt` 为准。
