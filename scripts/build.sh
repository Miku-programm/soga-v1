#!/bin/sh
# Build the independent reconstruction; no original executable is downloaded.
set -eu

PROJECT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
GO_TOOL=${GO:-go}
OUTPUT_DIR=${OUTPUT_DIR:-"$PROJECT_DIR/bin"}
case "$OUTPUT_DIR" in /*) ;; *) OUTPUT_DIR="$PROJECT_DIR/$OUTPUT_DIR" ;; esac
case "${1:-all}" in
  amd64|arm64) architectures=$1 ;;
  all) architectures='amd64 arm64' ;;
  -h|--help)
    printf '%s\n' '用法：GO=/path/to/go scripts/build.sh [all|amd64|arm64]' \
      '默认构建 Linux amd64 和 arm64；OUTPUT_DIR 默认为工程 bin/。' \
      '可选 VERSION=0.1.0 覆盖重建版本；不设置时使用源码常量。' \
      '使用 vendor/，不自动下载模块或 Go 工具链。'
    exit 0 ;;
  *) printf '%s\n' '错误：目标仅支持 all、amd64、arm64。' >&2; exit 2 ;;
esac
[ "$#" -le 1 ] || { printf '%s\n' '错误：多余的构建参数。' >&2; exit 2; }
command -v "$GO_TOOL" >/dev/null 2>&1 || { printf '找不到 Go：%s\n' "$GO_TOOL" >&2; exit 1; }
GO_TOOL=$(command -v "$GO_TOOL")
case "$GO_TOOL" in /*) ;; */*) GO_TOOL="$PWD/$GO_TOOL" ;; esac
link_flags='-s -w'
if [ -n "${VERSION:-}" ]; then
  case "$VERSION" in
    *[!A-Za-z0-9._+-]*) printf '%s\n' 'VERSION 仅允许字母、数字、点、下划线、加号、连字符。' >&2; exit 2 ;;
  esac
  link_flags="$link_flags -X main.reconstructionVersion=$VERSION"
fi
[ -f "$PROJECT_DIR/vendor/modules.txt" ] || {
  printf '%s\n' '缺少完整 vendor/；请先由源码维护者生成匹配 go.mod 的依赖包。' >&2
  exit 1
}
mkdir -p "$OUTPUT_DIR"
temporary=''
checksums=$(mktemp "$OUTPUT_DIR/.checksums.XXXXXX")
trap 'rm -f -- "$checksums"; if [ -n "$temporary" ]; then rm -f -- "$temporary"; fi' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
cd "$PROJECT_DIR"
for architecture in $architectures; do
  name="soga-reconstructed-linux-$architecture"
  temporary=$(mktemp "$OUTPUT_DIR/.$name.XXXXXX")
  printf '构建 %s\n' "$name"
  CGO_ENABLED=0 GOOS=linux GOARCH="$architecture" GOTOOLCHAIN=local \
    "$GO_TOOL" build -mod=vendor -trimpath -buildvcs=false -ldflags="$link_flags" \
    -o "$temporary" ./cmd/soga-reconstructed
  chmod 0755 "$temporary"
  mv -f -- "$temporary" "$OUTPUT_DIR/$name"
  temporary=''
  (cd "$OUTPUT_DIR" && sha256sum "$name") >> "$checksums"
done
mv -f -- "$checksums" "$OUTPUT_DIR/SHA256SUMS"
printf '构建完成：%s\n' "$OUTPUT_DIR"
