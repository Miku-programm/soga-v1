#!/bin/sh
# Remove the independent installation, preserving configuration and backups.
set -eu
stage=${DESTDIR:-}
while [ "${stage%/}" != "$stage" ]; do stage=${stage%/}; done
case "$stage" in ''|/*) ;; *) exit 2 ;; esac
if [ -z "$stage" ]; then
  [ "$(id -u)" -eq 0 ] || exit 1
  if [ -d /run/systemd/system ]; then
    systemctl disable --now soga.service
    listed=$(systemctl list-unit-files --full --no-legend 'soga@*.service')
    for unit in $(printf '%s\n' "$listed" | awk '$1 ~ /^soga@[A-Za-z0-9_-]+[.]service$/ {print $1}'); do
      systemctl disable --now "$unit"
    done
  fi
fi
rm -f "$stage/usr/bin/soga" "$stage/etc/systemd/system/soga.service" "$stage/etc/systemd/system/soga@.service"
if [ -f "$stage/usr/local/bin/soga" ] &&
   grep -q '^# soga-reconstructed manager launcher$' "$stage/usr/local/bin/soga"; then
  rm -f "$stage/usr/local/bin/soga"
fi
rm -rf "$stage/usr/local/soga" "$stage/usr/local/share/doc/soga-reconstructed"
if [ -z "$stage" ] && [ -d /run/systemd/system ]; then systemctl daemon-reload; fi
printf '%s\n' "已卸载；配置保留于 $stage/etc/soga，备份保留于 $stage/var/backups/soga。"
