#!/bin/sh
# Removes this reconstruction only. Configuration, certificates and state remain.
set -eu
stage=${DESTDIR:-}
while [ "${stage%/}" != "$stage" ]; do stage=${stage%/}; done
case "$stage" in ''|/*) ;; *) printf '%s\n' 'DESTDIR 必须是绝对路径。' >&2; exit 2 ;; esac
case "${1:-}" in
  '') ;;
  -h|--help)
    printf '%s\n' '用法：scripts/uninstall.sh' \
      '停止并卸载 soga-reconstructed 服务和程序；始终保留 /etc/soga-reconstructed。' \
      'DESTDIR=/绝对路径 仅清理该临时根，不调用宿主机 systemctl。'
    exit 0 ;;
  *) printf '%s\n' '不支持卸载参数；配置和证书始终保留。' >&2; exit 2 ;;
esac
[ "$#" -le 1 ] || exit 2
for directory in "$stage/usr/local/bin" "$stage/etc/systemd/system" "$stage/usr/local/share/doc/soga-reconstructed"; do
  [ ! -L "$directory" ] || { printf '拒绝清理符号链接目录：%s\n' "$directory" >&2; exit 1; }
done
if [ -z "$stage" ]; then
  [ "$(id -u)" -eq 0 ] || { printf '%s\n' '实际卸载需要 root。' >&2; exit 1; }
  if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
    # Enumerate only this exact service namespace; never stop original soga.
    loaded=$(systemctl list-units --all --full --plain --no-legend 'soga-reconstructed@*.service')
    installed=$(systemctl list-unit-files --full --no-legend 'soga-reconstructed@*.service')
    units=$(printf '%s\n%s\n' "$loaded" "$installed" |
      awk '$1 ~ /^soga-reconstructed@[A-Za-z0-9][A-Za-z0-9_-]*[.]service$/ {print $1}' | sort -u)
    for unit in $units; do systemctl disable --now "$unit"; done
  fi
fi
rm -f -- "$stage/usr/local/bin/soga-reconstructed" \
  "$stage/etc/systemd/system/soga-reconstructed@.service"
if [ -f "$stage/usr/local/bin/soga" ] && [ ! -L "$stage/usr/local/bin/soga" ] &&
   grep -q '^# soga-reconstructed manager launcher$' "$stage/usr/local/bin/soga"; then
  rm -f -- "$stage/usr/local/bin/soga"
fi
docdir="$stage/usr/local/share/doc/soga-reconstructed"
if [ ! -L "$docdir" ]; then
  rm -f -- "$docdir/部署说明.txt" "$docdir/LICENSE-VNet-SSR" "$docdir/LICENSE" \
    "$docdir/THIRD_PARTY_NOTICES.txt" "$docdir/uninstall.sh"
  rm -f -- "$docdir/manager.py" "$docdir/build-info.json"
  rm -rf -- "$docdir/LICENSES"
  if [ -d "$docdir" ]; then rmdir "$docdir" 2>/dev/null || :; fi
fi
if [ -z "$stage" ] && [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload
fi
printf '%s\n' 'soga-reconstructed 程序和服务模板已卸载。' \
  "配置、证书及状态保留于 $stage/etc/soga-reconstructed。"
