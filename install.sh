#!/usr/bin/env bash
# Follow the official install.sh parameter/configuration/startup flow for this
# independent build: https://github.com/vaxilu/soga/blob/master/install.sh
set -euo pipefail
umask 022

finish_install_service() {
  local had_config=$1 supplied_config=$2
  local unit=soga
  systemctl daemon-reload
  systemctl stop "$unit"
  systemctl enable "$unit"
  if [[ $had_config == true || $supplied_config == true ]]; then
    if systemctl restart "$unit"; then
      sleep 2
      if systemctl is-active --quiet "$unit"; then
        echo '安装和配置完成，服务已启动，并已设置开机自启。'
        return 0
      fi
    fi
    echo "服务未能启动，请检查配置并运行：journalctl -u $unit -n 100 --no-pager" >&2
    return 1
  fi
  printf '%s\n' '全新安装：尚未提供配置，暂不启动；已设置开机自启。' \
    '可重新执行本脚本并附上 type=... server_type=... webapi_url=... webapi_key=... node_id=...' \
    '也可编辑 /etc/soga/soga.conf，再运行 systemctl start soga'
}

# Allow isolated lifecycle tests to source the function without installing.
if [[ ${BASH_SOURCE[0]:-$0} != "$0" ]]; then return 0; fi

if [[ ${1:-} == --help || ${1:-} == -h ]]; then
  printf '%s\n' 'Usage: bash install.sh [release-tag] [key=value ...]' \
    '版本与配置参数可混合排列；不指定版本则安装最新版。' \
    '传入配置后自动写入并启动；重装保留已有配置并重启。' \
    '全新安装且未传入配置时，提示配置后再启动。'
  exit 0
fi
tag=latest
has_tag=false
configs=()
for arg in "$@"; do
  if [[ $arg == *=* ]]; then
    key=${arg%%=*}
    [[ $key =~ ^[A-Za-z_][A-Za-z0-9_]*$ && $arg != *$'\n'* && $arg != *$'\r'* ]] || {
      echo 'Invalid key=value configuration argument.' >&2; exit 2;
    }
    configs+=("$arg")
  elif [[ $has_tag == false ]]; then
    tag=${arg#v}
    has_tag=true
  else
    echo 'Only one release tag may be supplied.' >&2; exit 2
  fi
done
[[ $tag =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || { echo 'Invalid release tag.' >&2; exit 2; }
[[ $(uname -s) == Linux ]] || { echo 'This installer requires Linux.' >&2; exit 1; }
case "$(uname -m)" in
  x86_64|amd64) arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) echo 'Supported architectures: amd64, arm64.' >&2; exit 1 ;;
esac
# DESTDIR is an existing installer convention, used for isolated staging checks.
if [[ -z ${DESTDIR:-} && $EUID -ne 0 ]]; then
  echo 'Run with sudo or as root.' >&2
  exit 1
fi
if [[ -z ${DESTDIR:-} ]]; then
  command -v systemctl >/dev/null || { echo 'This installer requires systemd.' >&2; exit 1; }
fi
# Match the official dependency and certificate-client setup on real hosts.
if [[ -z ${DESTDIR:-} ]]; then
  if command -v apt-get >/dev/null; then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y curl wget tar cron socat tzdata python3 ca-certificates openssl
  elif command -v dnf >/dev/null; then
    dnf install -y curl wget tar cronie socat tzdata python3 ca-certificates openssl
  elif command -v yum >/dev/null; then
    yum install -y epel-release
    yum install -y curl wget tar crontabs socat tzdata python3 ca-certificates openssl
  else
    echo '未检测到受支持的包管理器（apt、dnf、yum）。' >&2
    exit 1
  fi
  if [[ ! -x /root/.acme.sh/acme.sh ]]; then
    acme_setup=$(mktemp)
    if ! curl -fLSs --retry 3 https://get.acme.sh -o "$acme_setup"; then
      rm -f "$acme_setup"; exit 1
    fi
    sh "$acme_setup" || { rm -f "$acme_setup"; exit 1; }
    rm -f "$acme_setup"
  fi
  /root/.acme.sh/acme.sh --set-default-ca --server letsencrypt
fi
for program in curl tar sha256sum mktemp awk; do
  command -v "$program" >/dev/null || { echo "Missing dependency: $program" >&2; exit 1; }
done
base=https://github.com/Miku-programm/soga-v1/releases
if [[ $tag == latest ]]; then
  base=$base/latest/download
else
  base=$base/download/$tag
fi
scratch=$(mktemp -d)
trap 'rm -rf -- "$scratch"' EXIT
asset="soga-linux-${arch}.tar.gz"
printf "架构: %s\n开始安装 soga %s\n" "$arch" "$tag"
curl --fail --show-error --silent --location --retry 3 --connect-timeout 20 \
  --max-time 600 --proto '=https' --proto-redir '=https' \
  "$base/$asset" -o "$scratch/$asset"
curl --fail --show-error --silent --location --retry 3 --connect-timeout 20 \
  --max-time 60 --proto '=https' --proto-redir '=https' \
  "$base/SHA256SUMS" -o "$scratch/SHA256SUMS"
awk -v name="$asset" '$2 == name {print}' "$scratch/SHA256SUMS" > "$scratch/selected.sha256"
[[ $(wc -l < "$scratch/selected.sha256") -eq 1 ]] || {
  echo 'Release checksum is missing or duplicated.' >&2; exit 1;
}
(cd "$scratch" && sha256sum --check --strict selected.sha256)
tar -xzf "$scratch/$asset" -C "$scratch" --no-same-owner
project="$scratch/soga-reconstructed"
[[ -f $project/scripts/install.sh ]] || { echo 'Invalid release layout.' >&2; exit 1; }
config_root="${DESTDIR:-}/etc/soga"
had_config=false
[[ ! -f $config_root/soga.conf && ! -f ${DESTDIR:-}/etc/soga-reconstructed/soga.conf ]] || had_config=true
sh "$project/scripts/install.sh" "$arch"
supplied_config=false
if [[ ${#configs[@]} -gt 0 ]]; then
  "${DESTDIR:-}/usr/local/soga/soga" \
    instance -root "$config_root" config default "${configs[@]}"
  supplied_config=true
  echo '已写入命令行配置（不回显密钥值）。'
fi
if [[ -z ${DESTDIR:-} ]]; then
  finish_install_service "$had_config" "$supplied_config"
  printf '\n%s\n' \
    '输入 soga 打开交互式管理菜单。' \
    '查看日志：journalctl -u soga -f'
else
  echo '临时目录安装完成；未操作宿主 systemd。'
fi

printf '%s\n' 'soga 管理脚本使用方法:' \
  '  soga                        显示管理菜单' \
  '  soga list                   列出实例及状态' \
  '  soga new NAME [key=value]   新建实例' \
  '  soga config [NAME]         查看配置' \
  '  soga start/stop/restart [NAME]' \
  '  soga enable/disable [NAME]' \
  '  soga log [NAME] [-f]        查看日志' \
  '  soga update [version]      更新程序' \
  '  soga self-update           更新管理菜单' \
  '  soga uninstall             完全卸载'
