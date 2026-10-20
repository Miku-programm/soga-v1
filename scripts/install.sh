#!/bin/sh
# Install the independent build using the official soga directory/service layout.
set -eu
umask 022
PROJECT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
stage=${DESTDIR:-}
while [ "${stage%/}" != "$stage" ]; do stage=${stage%/}; done
case "$stage" in ''|/*) ;; *) echo 'DESTDIR 必须是绝对路径。' >&2; exit 2 ;; esac
case "${1:-$(uname -m)}" in
  amd64|x86_64) architecture=amd64 ;;
  arm64|aarch64) architecture=arm64 ;;
  *) echo '仅支持 amd64/arm64。' >&2; exit 2 ;;
esac
if [ -z "$stage" ]; then
  [ "$(id -u)" -eq 0 ] || { echo '必须使用 root。' >&2; exit 1; }
  command -v python3 >/dev/null || { echo '请使用根目录 install.sh 安装依赖。' >&2; exit 1; }
fi
binary="$PROJECT_DIR/bin/soga-reconstructed-linux-$architecture"
[ -f "$binary" ] && [ -d "$PROJECT_DIR/LICENSES" ] || { echo '发布包不完整。' >&2; exit 1; }
program="$stage/usr/local/soga"
config="$stage/etc/soga"
units="$stage/etc/systemd/system"
doc="$stage/usr/local/share/doc/soga-reconstructed"
for directory in "$program" "$config" "$units" "$doc" "$stage/usr/bin" "$stage/usr/local/bin"; do
  [ ! -L "$directory" ] || { echo "拒绝写入符号链接目录：$directory" >&2; exit 1; }
done
# A previous independent launcher would shadow /usr/bin/soga in PATH.
old_launcher="$stage/usr/local/bin/soga"
if [ -e "$old_launcher" ] || [ -L "$old_launcher" ]; then
  [ ! -L "$old_launcher" ] && grep -q '^# soga-reconstructed manager launcher$' "$old_launcher" || {
    echo '存在其他 /usr/local/bin/soga，请先备份移走以避免命令遮蔽。' >&2; exit 1;
  }
fi
backup="$stage/var/backups/soga/$(date +%Y%m%d-%H%M%S)-$$"
for relative in usr/local/soga usr/bin/soga etc/systemd/system/soga.service etc/systemd/system/soga@.service; do
  if [ -e "$stage/$relative" ] || [ -L "$stage/$relative" ]; then
    mkdir -p "$backup/$(dirname "$relative")"
    cp -a "$stage/$relative" "$backup/$relative"
  fi
done
[ ! -d "$backup" ] || printf '原安装文件已备份：%s\n' "$backup"
# Preserve every existing official configuration. Migrate the earlier build only
# when the official directory does not contain its own default configuration.
if [ ! -e "$config/soga.conf" ] && [ -f "$stage/etc/soga-reconstructed/soga.conf" ]; then
  install -d -m 0700 "$config"
  cp -a -n "$stage/etc/soga-reconstructed/." "$config/"
  echo '已迁移先前重建版配置至 /etc/soga；原目录保留。'
fi
install -d -m 0755 "$program" "$units" "$doc" "$stage/usr/bin"
[ -d "$config" ] || install -d -m 0700 "$config"
# Replace executables atomically, allowing running instances to finish normally.
tmp=$(mktemp "$program/.soga.XXXXXX")
trap 'rm -f "$tmp"' EXIT
install -m 0755 "$binary" "$tmp"
mv -f "$tmp" "$program/soga"
for name in soga.conf blockList dns.yml routes.toml; do
  if [ ! -e "$config/$name" ] && [ ! -L "$config/$name" ]; then
    install -m 0600 "$PROJECT_DIR/examples/$name" "$config/$name"
  fi
done
if [ ! -e "$config/whiteList" ] && [ ! -L "$config/whiteList" ]; then
  install -m 0600 /dev/null "$config/whiteList"
fi
for name in default template; do
  if [ "$name" = default ]; then unit=soga.service; instance=default; else unit=soga@.service; instance=%i; fi
  cat > "$program/$unit" <<UNIT
[Unit]
Description=Independent soga reconstruction instance $instance
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/etc/soga
ExecStart=/usr/local/soga/soga instance-run $instance
Restart=on-failure
RestartSec=5s
TimeoutStopSec=45s
KillMode=control-group
LimitNOFILE=1048576
UMask=0077

[Install]
WantedBy=multi-user.target
UNIT
  install -m 0644 "$program/$unit" "$units/$unit"
done
install -m 0644 "$PROJECT_DIR/examples/部署说明.txt" "$doc/部署说明.txt"
install -m 0644 "$PROJECT_DIR/LICENSE" "$doc/LICENSE"
install -m 0644 "$PROJECT_DIR/THIRD_PARTY_NOTICES.txt" "$doc/THIRD_PARTY_NOTICES.txt"
cp -R "$PROJECT_DIR/LICENSES" "$doc/"
install -m 0755 "$PROJECT_DIR/scripts/uninstall.sh" "$doc/uninstall.sh"
install -m 0644 "$PROJECT_DIR/scripts/manager.py" "$doc/manager.py"
launcher_tmp=$(mktemp "$stage/usr/bin/.soga.XXXXXX")
install -m 0755 "$PROJECT_DIR/scripts/soga" "$launcher_tmp"
mv -f "$launcher_tmp" "$stage/usr/bin/soga"
if [ -f "$PROJECT_DIR/BUILD-INFO.json" ]; then
  install -m 0644 "$PROJECT_DIR/BUILD-INFO.json" "$doc/build-info.json"
else
  rm -f "$doc/build-info.json"
fi
if [ -f "$old_launcher" ]; then rm -f "$old_launcher"; fi
# Stop only previously installed reconstruction services during migration.
if [ -z "$stage" ] && [ -d /run/systemd/system ]; then
  old_loaded=$(systemctl list-units --all --plain --no-legend 'soga-reconstructed@*.service')
  old_installed=$(systemctl list-unit-files --plain --no-legend 'soga-reconstructed@*.service')
  old_units=$(printf '%s\n%s\n' "$old_loaded" "$old_installed" | awk '$1 ~ /^soga-reconstructed@[A-Za-z0-9_-]+[.]service$/ {print $1}' | sort -u)
  for old in $old_units; do systemctl disable --now "$old"; done
  systemctl daemon-reload
fi
printf 'soga 安装完成，配置目录：%s\n输入 soga 打开管理菜单。\n' "$config"
