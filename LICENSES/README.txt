第三方许可证与来源索引

本目录按工程内原路径镜像保存第三方许可、版权、NOTICE、COPYING、
PATENTS、AUTHORS、ATTRIBUTION 等文件，保留原始字节，不合并或改写
上游版权。SOURCE/PROVENANCE 文件和地理数据 README 作为来源材料
一同保留；它们不替代许可证。

查找方法
  manifest.json：每个复制文件的来源、长度、SHA256，以及 Go 模块版本。
  MODULES.tsv：vendor/modules.txt 中每个模块及其许可文件对应关系。
  SHA256SUMS：复制文件的校验值；在本目录执行 sha256sum -c SHA256SUMS。
  vendor/：按实际模块路径保留，包含嵌套子组件的单独许可。
  third_party/：Xray、sing-box 本地副本许可与修改来源说明。
  proxy/：移植的 SSR、VMess、SS AEAD 和 simple-obfs 来源/许可。
  certificates/bundled/：内置 acme.sh 的许可及版本/文件校验信息。
  geodata/bundled/：GeoIP/GeoSite 许可、DB-IP 署名和数据下载来源。
  testdata/ssr-reference/：独立 SSR Python 测试参考源码的许可。
  go-standard-library/：构建所用 Go 标准库及其内置依赖的许可和 PATENTS。

MODULES.tsv 中 root-legal-file-present 仅说明对应模块根目录或父目录
存在许可材料；它不代表该模块的每个文件使用同一许可证，也不是对
许可证兼容性的法律判定。nested_legal_files 明确保留子组件的例外。
vendor 列表可能包含测试依赖和条件编译依赖；清单不声称所有模块都
出现在每个架构的最终二进制中。

本工程使用公开组件构建独立兼容实现。这里的模块版本与许可证描述
的是此源码包，不证明原版 soga 使用了相同组件或版本。原版程序的
许可、商标或源码权利不由本清单授予。

刷新方法（先完成 go mod vendor，刷新期间不能并行改写 vendor）：
  python3 -B LICENSES/collect.py
需要同时刷新 Go 标准库通知时：
  python3 -B LICENSES/collect.py --goroot /path/to/go

脚本只写 LICENSES，不改原始第三方文件。缺少某个实际 vendored 模块
的根许可文件会退出非零并列出模块；应调查其真实来源，不可据项目名
自行填写许可。普通刷新会保留已收集的 Go 标准库通知；构建工具版本
变化时应使用 --goroot 更新。

分发时请保留根 LICENSE、THIRD_PARTY_NOTICES.txt、本目录和各组件
源码目录里的原有许可/版权。安装脚本及 Dockerfile 会将前三者复制到
/usr/local/share/doc/soga-reconstructed。完整可构建源码包另附 vendor
和本地修改；单独的 LICENSES 目录不等于对应源代码。
