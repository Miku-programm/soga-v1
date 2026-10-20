#!/bin/sh
# Sourceable helpers: an empty systemd listing can return 1 without an error.
list_legacy_services() {
  migration_errors=$(mktemp)
  if migration_output=$(systemctl "$@" 2>"$migration_errors"); then
    migration_status=0
  else
    migration_status=$?
  fi
  if [ "$migration_status" -ne 0 ]; then
    if [ "$migration_status" -ne 1 ] || [ -n "$migration_output" ] || [ -s "$migration_errors" ]; then
      printf '读取旧服务列表失败（退出码 %s）：\n' "$migration_status" >&2
      cat "$migration_errors" >&2
      rm -f "$migration_errors"
      return "$migration_status"
    fi
  fi
  rm -f "$migration_errors"
  printf '%s\n' "$migration_output"
}

retire_legacy_services() {
  old_loaded=$(list_legacy_services list-units --all --plain --no-legend 'soga-reconstructed@*.service') || return $?
  old_installed=$(list_legacy_services list-unit-files --plain --no-legend 'soga-reconstructed@*.service') || return $?
  old_units=$(printf '%s\n%s\n' "$old_loaded" "$old_installed" |
    awk '$1 ~ /^soga-reconstructed@[A-Za-z0-9_-]+[.]service$/ {print $1}' | sort -u)
  for old in $old_units; do
    systemctl disable --now "$old" || {
      printf '停止旧服务失败：%s；请检查该服务后重新安装。\n' "$old" >&2
      return 1
    }
  done
  systemctl daemon-reload || return $?
}
