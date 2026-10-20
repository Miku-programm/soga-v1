#!/bin/sh
# Installs only the binary already built inside this source project.
set -eu
umask 022

PROJECT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
stage=${DESTDIR:-}
while [ "${stage%/}" != "$stage" ]; do stage=${stage%/}; done
case "$stage" in ''|/*) ;; *) printf '%s\n' 'DESTDIR 必须是绝对路径。' >&2; exit 2 ;; esac
case "${1:-}" in
  amd64|arm64) architecture=$1 ;;
  '')
    case "$(uname -m)" in
      x86_64|amd64) architecture=amd64 ;;
      aarch64|arm64) architecture=arm64 ;;
      *) printf '%s\n' '无法识别架构，请显式指定 amd64 或 arm64。' >&2; exit 2 ;;
    esac ;;
  -h|--help)
    printf '%s\n' '用法：scripts/install.sh [amd64|arm64]' \
      '从本工程 bin/ 安装；DESTDIR=/绝对路径 可安装到临时根。' \
      '保留已有配置；不启用、不启动、不重启服务。'
    exit 0 ;;
  *) printf '%s\n' '架构仅支持 amd64、arm64。' >&2; exit 2 ;;
esac
[ "$#" -le 1 ] || { printf '%s\n' '错误：多余的安装参数。' >&2; exit 2; }
if [ -z "$stage" ]; then
  [ "$(uname -s)" = Linux ] || { printf '%s\n' '实际安装仅支持 Linux。' >&2; exit 1; }
  [ "$(id -u)" -eq 0 ] || { printf '%s\n' '实际安装需要 root；临时验证请使用 DESTDIR。' >&2; exit 1; }
  if ! command -v python3 >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then
      apt-get update
      apt-get install -y python3
    elif command -v dnf >/dev/null 2>&1; then
      dnf install -y python3
    elif command -v yum >/dev/null 2>&1; then
      yum install -y python3
    else
      printf '%s\n' '管理菜单需要 Python 3，请先安装 python3。' >&2
      exit 1
    fi
  fi
fi
binary="$PROJECT_DIR/bin/soga-reconstructed-linux-$architecture"
[ -f "$binary" ] && [ ! -L "$binary" ] || {
  printf '找不到已编译程序：%s；请先运行 scripts/build.sh。\n' "$binary" >&2; exit 1;
}
for source in LICENSE THIRD_PARTY_NOTICES.txt; do
  [ -f "$PROJECT_DIR/$source" ] || {
    printf '缺少 %s；请使用包含完整许可文件的源码发布包。\n' "$source" >&2; exit 1;
  }
done
[ -d "$PROJECT_DIR/LICENSES" ] && [ -n "$(find "$PROJECT_DIR/LICENSES" -type f -print -quit)" ] || {
  printf '%s\n' '缺少完整 LICENSES/；请先由维护者汇集依赖许可后再安装。' >&2; exit 1;
}
bindir="$stage/usr/local/bin"
configdir="$stage/etc/soga-reconstructed"
unitdir="$stage/etc/systemd/system"
docdir="$stage/usr/local/share/doc/soga-reconstructed"
for directory in "$bindir" "$configdir" "$unitdir" "$docdir"; do
  [ ! -L "$directory" ] || { printf '拒绝写入符号链接目录：%s\n' "$directory" >&2; exit 1; }
done
[ ! -L "$docdir/LICENSES" ] || { printf '%s\n' '拒绝写入符号链接 LICENSES 目录。' >&2; exit 1; }
if [ -e "$bindir/soga" ] || [ -L "$bindir/soga" ]; then
  [ ! -L "$bindir/soga" ] && grep -q '^# soga-reconstructed manager launcher$' "$bindir/soga" || {
    printf '%s\n' '已有其他 /usr/local/bin/soga；请先将其备份移走再安装此管理菜单。' >&2
    exit 1
  }
fi
install -d -m 0755 "$bindir" "$unitdir" "$docdir"
if [ ! -d "$configdir" ]; then install -d -m 0700 "$configdir"; fi
temporary=$(mktemp "$bindir/.soga-reconstructed.XXXXXX")
unit_temporary=''
trap 'rm -f -- "$temporary"; if [ -n "$unit_temporary" ]; then rm -f -- "$unit_temporary"; fi' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
install -m 0755 "$binary" "$temporary"
mv -f -- "$temporary" "$bindir/soga-reconstructed"
if [ ! -e "$configdir/soga.conf" ] && [ ! -L "$configdir/soga.conf" ]; then
  install -m 0600 "$PROJECT_DIR/examples/soga.conf" "$configdir/soga.conf"
  printf '%s\n' '已创建示例配置；必须按实际面板、节点和凭据修改后才能启动。'
else
  printf '%s\n' '已有 soga.conf 已保留。'
fi
unit_temporary=$(mktemp "$unitdir/.soga-reconstructed.XXXXXX")
cat > "$unit_temporary" <<'UNIT'
[Unit]
Description=Independent soga reconstruction instance %i
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/etc/soga-reconstructed
ExecStart=/usr/local/bin/soga-reconstructed instance-run %i
Restart=on-failure
RestartSec=5s
TimeoutStopSec=45s
KillMode=control-group
LimitNOFILE=1048576
UMask=0077

[Install]
WantedBy=multi-user.target
UNIT
chmod 0644 "$unit_temporary"
mv -f -- "$unit_temporary" "$unitdir/soga-reconstructed@.service"
install -m 0644 "$PROJECT_DIR/examples/部署说明.txt" "$docdir/部署说明.txt"
install -m 0644 "$PROJECT_DIR/LICENSE" "$docdir/LICENSE"
install -m 0644 "$PROJECT_DIR/THIRD_PARTY_NOTICES.txt" "$docdir/THIRD_PARTY_NOTICES.txt"
install -d -m 0755 "$docdir/LICENSES"
cp -R "$PROJECT_DIR/LICENSES/." "$docdir/LICENSES/"
find "$docdir/LICENSES" -type d -exec chmod 0755 {} +
find "$docdir/LICENSES" -type f -exec chmod 0644 {} +
install -m 0755 "$PROJECT_DIR/scripts/uninstall.sh" "$docdir/uninstall.sh"
install -m 0644 "$PROJECT_DIR/scripts/manager.py" "$docdir/manager.py"
install -m 0755 "$PROJECT_DIR/scripts/soga" "$bindir/soga"
if [ -f "$PROJECT_DIR/BUILD-INFO.json" ]; then
  install -m 0644 "$PROJECT_DIR/BUILD-INFO.json" "$docdir/build-info.json"
else
  rm -f -- "$docdir/build-info.json"
fi
if [ -z "$stage" ] && [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload
fi
printf '安装完成，配置目录：%s\n' "$configdir"
printf '%s\n' '输入 soga 打开交互式管理菜单。'
printf '%s\n' '服务未启动、未设为开机启动。配置完成后显式执行：' \
  '  sudo soga-reconstructed instance start default' \
  '  sudo soga-reconstructed instance enable default'
