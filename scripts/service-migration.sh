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
  # Refresh LoadState before deciding whether a legacy unit file still exists.
  systemctl daemon-reload || return $?
  old_loaded=$(list_legacy_services list-units --all --plain --no-legend 'soga-reconstructed@*.service') || return $?
  old_installed=$(list_legacy_services list-unit-files --plain --no-legend 'soga-reconstructed@*.service') || return $?
  old_units=$(printf '%s\n%s\n' "$old_loaded" "$old_installed" |
    awk '$1 ~ /^soga-reconstructed@[A-Za-z0-9_-]+[.]service$/ {print $1}' | sort -u)
  for old in $old_units; do
    if old_properties=$(systemctl show "$old" --property=LoadState --property=ActiveState --property=UnitFileState); then
      old_show_status=0
    else
      old_show_status=$?
    fi
    old_load=$(printf '%s\n' "$old_properties" | sed -n 's/^LoadState=//p')
    old_active=$(printf '%s\n' "$old_properties" | sed -n 's/^ActiveState=//p')
    old_file=$(printf '%s\n' "$old_properties" | sed -n 's/^UnitFileState=//p')
    if [ -z "$old_load" ] || [ -z "$old_active" ] ||
       { [ "$old_show_status" -ne 0 ] && [ "$old_load" != not-found ]; }; then
      printf '读取旧服务状态失败：%s；为避免端口冲突，安装已停止。\n' "$old" >&2
      return 1
    fi
    # A missing file can still have a live process. Stop that process first.
    case "$old_active" in
      inactive|failed) ;;
      *)
        systemctl stop "$old" || {
          printf '停止旧服务失败：%s；请检查该服务后重新安装。\n' "$old" >&2
          return 1
        } ;;
    esac
    if [ "$old_load" != not-found ]; then
      case "$old_file" in
        enabled|enabled-runtime|linked|linked-runtime|alias)
          systemctl disable "$old" || {
            printf '取消旧服务自启失败：%s。\n' "$old" >&2
            return 1
          } ;;
      esac
    else
      printf '旧服务文件已不存在，跳过禁用：%s\n' "$old"
    fi
    if [ "$old_active" = failed ]; then
      # Resetting a stale failure is cosmetic; the unit may disappear meanwhile.
      if ! systemctl reset-failed "$old"; then
        printf '旧服务失败记录已消失或无法重置：%s；继续安装。\n' "$old" >&2
      fi
    fi
  done
  systemctl daemon-reload || return $?
}
