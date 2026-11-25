# syntax=docker/dockerfile:1
# HomeXDR server image: console, agent API, syslog intake, plus agent binaries for download.
# Build from the repository root:  docker build -t homexdr/server .
# deploy/update/homexdr-update.sh builds it with VERSION, COMMIT and COMMIT_TIME set.

# The web and Go stages run on the build machine: the web bundle and the agent binaries are
# the same for every image platform, and only the server binary is built for the target.
FROM --platform=$BUILDPLATFORM node:22-alpine AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
RUN npm run build

# quill signs the macOS agents on Linux. The patch pins the signing certificate in the
# signature's requirement (see deploy/macsign/README.md); upstream writes only the identifier.
FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS quill
ENV CGO_ENABLED=0
COPY deploy/macsign/quill-pin-leaf.patch /tmp/
RUN apk add --no-cache patch >/dev/null && \
    d=$(go mod download -json github.com/anchore/quill@v0.7.1 | sed -n 's/.*"Dir": "\(.*\)",/\1/p') && \
    cp -r "$d" /tmp/quill && chmod -R u+w /tmp/quill && cd /tmp/quill && \
    patch -p1 </tmp/quill-pin-leaf.patch && go build -trimpath -o /out/quill ./cmd/quill

FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS build
WORKDIR /src
ENV CGO_ENABLED=0
COPY shared/ shared/
COPY server/go.mod server/go.sum server/
COPY agent/go.mod agent/go.sum agent/
RUN cd server && go mod download && cd ../agent && go mod download
COPY server/ server/
COPY agent/ agent/
COPY --from=web /src/web/dist/ server/internal/webui/dist/
ARG VERSION=dev
ARG COMMIT=unknown
# Unix time of the commit; agents only update to builds with a later commit time.
ARG COMMIT_TIME=0
ARG TARGETOS
ARG TARGETARCH
RUN V=github.com/Netdoodle/homexdr/shared/version && \
    LDFLAGS="-s -w -X $V.Version=${VERSION} -X $V.Commit=${COMMIT} -X $V.CommitTime=${COMMIT_TIME}" && \
    cd /src/server && \
    GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -ldflags "$LDFLAGS" -o /out/homexdr-server ./cmd/homexdr-server && \
    go build -trimpath -ldflags "$LDFLAGS" -o /tmp/homexdr-server-native ./cmd/homexdr-server && \
    mkdir -p /out/downloads /out/data && cd /src/agent && \
    for target in linux/amd64 linux/arm64 windows/amd64 darwin/amd64 darwin/arm64; do \
      os=${target%/*}; arch=${target#*/}; ext=""; [ "$os" = windows ] && ext=.exe; \
      GOOS=$os GOARCH=$arch go build -trimpath -ldflags "$LDFLAGS" \
        -o /out/downloads/homexdr-agent-$os-$arch$ext ./cmd/homexdr-agent || exit 1; \
    done
# Sign the macOS agents when the build has a certificate (BuildKit secrets macsign_p12 and
# macsign_pass); otherwise they keep the linker's ad-hoc signature. Signing comes before the
# checksums and the release manifest, which cover the signed files.
COPY --from=quill /out/quill /usr/local/bin/quill
COPY deploy/macsign/sign.sh /usr/local/bin/macsign
RUN --mount=type=secret,id=macsign_p12 --mount=type=secret,id=macsign_pass \
    macsign com.homexdr.agent /out/downloads/homexdr-agent-darwin-amd64 /out/downloads/homexdr-agent-darwin-arm64 && \
    cd /out/downloads && sha256sum homexdr-agent-* > SHA256SUMS && \
    /tmp/homexdr-server-native release-manifest /out/downloads

FROM gcr.io/distroless/static-debian12:nonroot
ARG VERSION=dev
ARG COMMIT=unknown
LABEL org.opencontainers.image.title="homexdr-server" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}" \
      org.opencontainers.image.source="https://github.com/Netdoodle/HomeXDR" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=build /out/homexdr-server /usr/local/bin/homexdr-server
COPY --from=build /out/downloads/ /usr/share/homexdr/downloads/
COPY rules/ /usr/share/homexdr/rules/
COPY --from=build --chown=65532:65532 /out/data /data
ENV HOMEXDR_DATA_DIR=/data \
    HOMEXDR_RULES_DIR=/usr/share/homexdr/rules \
    HOMEXDR_DOWNLOADS_DIR=/usr/share/homexdr/downloads \
    HOMEXDR_SIGNATURES_DIR=/usr/share/homexdr/signatures \
    HOMEXDR_HTTP_ADDR=:8080 \
    HOMEXDR_AGENT_ADDR=:8443 \
    HOMEXDR_SYSLOG_ADDR=:5514
EXPOSE 8080/tcp 8443/tcp 5514/udp 5514/tcp 2055/udp
VOLUME /data
USER 65532:65532
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD ["/usr/local/bin/homexdr-server", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/homexdr-server"]
CMD ["serve"]
