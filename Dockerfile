# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM golang:1.27.3-alpine AS build
ARG TARGETARCH
ARG VERSION
WORKDIR /src
COPY . .
RUN test -f LICENSE && test -f THIRD_PARTY_NOTICES.txt && test -d LICENSES \
    || { echo "需要包含 LICENSE、THIRD_PARTY_NOTICES.txt、LICENSES/ 的完整源码发布包。" >&2; exit 1; }
RUN GO=/usr/local/go/bin/go OUTPUT_DIR=/out VERSION="$VERSION" sh scripts/build.sh "${TARGETARCH:-amd64}" \
    && cp "/out/soga-reconstructed-linux-${TARGETARCH:-amd64}" /out/soga-reconstructed

FROM debian:bookworm-slim
# HTTP-01 standalone in the embedded acme.sh requires socat.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl openssl socat tzdata \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /etc/soga-reconstructed /usr/share/doc/soga-reconstructed \
    && chmod 0700 /etc/soga-reconstructed
COPY --from=build /out/soga-reconstructed /usr/local/bin/soga-reconstructed
COPY --from=build /src/LICENSE /src/THIRD_PARTY_NOTICES.txt /usr/share/doc/soga-reconstructed/
COPY --from=build /src/LICENSES/ /usr/share/doc/soga-reconstructed/LICENSES/
WORKDIR /etc/soga-reconstructed
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/soga-reconstructed"]
CMD ["serve", "-c", "/etc/soga-reconstructed/soga.conf", "-b", "/etc/soga-reconstructed/blockList", "-w", "/etc/soga-reconstructed/whiteList", "-d", "/etc/soga-reconstructed/dns.yml", "-r", "/etc/soga-reconstructed/routes.toml", "-state-dir", "/etc/soga-reconstructed/state"]
