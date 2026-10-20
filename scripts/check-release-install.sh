#!/usr/bin/env bash
# Exercise the download wrapper using locally built release assets.
set -euo pipefail
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
scratch=$(mktemp -d)
trap 'rm -rf -- "$scratch"' EXIT
mkdir -p "$scratch/tools"
cat > "$scratch/tools/curl" <<'CURL'
#!/usr/bin/env bash
set -euo pipefail
url=''
out=''
while [[ $# -gt 0 ]]; do
  case $1 in
    -o) out=$2; shift 2 ;;
    https://*) url=$1; shift ;;
    *) shift ;;
  esac
done
[[ $url == https://github.com/Miku-programm/soga-v1/releases/* ]]
printf '%s\n' "$url" >> "$TEST_REQUESTS"
cp "$TEST_ASSETS/${url##*/}" "$out"
CURL
chmod +x "$scratch/tools/curl"
export TEST_ASSETS="$root/dist"
export TEST_REQUESTS="$scratch/download-requests"
export PATH="$scratch/tools:$PATH"
DESTDIR="$scratch/stage" bash "$root/install.sh"
cmp "$root/bin/soga-reconstructed-linux-amd64" "$scratch/stage/usr/local/bin/soga-reconstructed"
printf '\n# preserve-this-setting\n' >> "$scratch/stage/etc/soga-reconstructed/soga.conf"
DESTDIR="$scratch/stage" bash "$root/install.sh"
grep -q preserve-this-setting "$scratch/stage/etc/soga-reconstructed/soga.conf"
mkdir "$scratch/bad-assets"
cp "$root/dist/SHA256SUMS" "$scratch/bad-assets/SHA256SUMS"
printf 'corrupted archive\n' > "$scratch/bad-assets/soga-linux-amd64.tar.gz"
if TEST_ASSETS="$scratch/bad-assets" DESTDIR="$scratch/rejected" bash "$root/install.sh"; then
  echo 'Corrupted release unexpectedly installed.' >&2
  exit 1
fi
[[ ! -e $scratch/rejected/usr/local/bin/soga-reconstructed ]]

# Official-style key=value arguments, including values that must not be
# interpreted as sed expressions or shell commands.
secret='fixture=a&b/c\ d'
: > "$TEST_REQUESTS"
DESTDIR="$scratch/configured" bash "$root/install.sh" \
  type=v2board build-fixture webapi_url=https://panel.example.invalid \
  "webapi_key=$secret" node_id=2 node_id=3 > "$scratch/config-output"
grep -Fxq 'https://github.com/Miku-programm/soga-v1/releases/download/build-fixture/soga-linux-amd64.tar.gz' "$TEST_REQUESTS"
conf="$scratch/configured/etc/soga-reconstructed/soga.conf"
grep -Fxq "webapi_key=$secret" "$conf"
grep -Fxq 'node_id=3' "$conf"
[[ $(grep -c '^node_id=' "$conf") -eq 1 ]]
if grep -Fq "$secret" "$scratch/config-output"; then
  echo 'Installer printed the configuration secret.' >&2; exit 1
fi
before=$(sha256sum "$conf")
if DESTDIR="$scratch/configured" bash "$root/install.sh" $'webapi_key=a\nnode_id=999'; then
  echo 'Multiline configuration unexpectedly accepted.' >&2; exit 1
fi
[[ $(sha256sum "$conf") == "$before" ]]

# Verify service decisions with a command stub, never the host systemd.
source "$root/install.sh"
service_log="$scratch/service-calls"
systemctl() {
  printf '%s\n' "$*" >> "$service_log"
  if [[ $1 == is-active && ${simulate_failure:-false} == true ]]; then return 1; fi
  return 0
}
sleep() { :; }
finish_install_service false false
! grep -q '^restart ' "$service_log"
grep -Fxq 'enable soga-reconstructed@default' "$service_log"
: > "$service_log"
finish_install_service false true
grep -Fxq 'restart soga-reconstructed@default' "$service_log"
: > "$service_log"
finish_install_service true false
grep -Fxq 'restart soga-reconstructed@default' "$service_log"
simulate_failure=true
if finish_install_service false true; then
  echo 'Failed service unexpectedly reported success.' >&2; exit 1
fi
echo 'PASS: install, config preservation/arguments, secret redaction, checksum rejection, and service lifecycle.'
