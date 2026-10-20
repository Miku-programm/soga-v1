#!/usr/bin/env bash
# Download a compiled independent reconstruction from this repository's releases.
set -euo pipefail
umask 022

if [[ ${1:-} == --help || ${1:-} == -h ]]; then
  printf '%s\n' 'Usage: bash install.sh [release-tag]' \
    'Downloads the latest build by default. Existing configuration is preserved.' \
    'Installs only; fill in the panel configuration before starting the service.'
  exit 0
fi
[[ $# -le 1 ]] || { echo 'Only one release tag may be supplied.' >&2; exit 2; }
tag=${1:-latest}
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
echo "Downloading $asset ($tag)..."
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
sh "$project/scripts/install.sh" "$arch"
if [[ -z ${DESTDIR:-} ]]; then
  printf '\n%s\n' \
    '安装完成。首次启动前请编辑 /etc/soga-reconstructed/soga.conf：' \
    'webapi_url 填你的面板地址；webapi_key 填面板后台「节点 → 通讯密钥」。' \
    '同时填写 type、server_type、node_id。无需填写 soga_key；soga_panel_url/key 留空。' \
    '配置完成后启动：systemctl enable --now soga-reconstructed@default' \
    '查看日志：journalctl -u soga-reconstructed@default -f' \
    '已有配置已保留；重复安装不会自动重启服务。'
fi
