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
cp "$TEST_ASSETS/${url##*/}" "$out"
CURL
chmod +x "$scratch/tools/curl"
export TEST_ASSETS="$root/dist"
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
echo 'PASS: staged install, configuration preservation, and checksum rejection.'
