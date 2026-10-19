# syntax=docker/dockerfile:1
# HomeXDR server image: console, agent API, syslog intake, plus agent binaries for download.
# Build from the repository root:  docker build -t homexdr/server .

FROM node:22-alpine AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
RUN npm run build

FROM golang:1.27-alpine AS build
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
RUN LDFLAGS="-s -w -X github.com/Netdoodle/homexdr/shared/version.Version=${VERSION} -X github.com/Netdoodle/homexdr/shared/version.Commit=${COMMIT}" && \
    cd /src/server && go build -trimpath -ldflags "$LDFLAGS" -o /out/homexdr-server ./cmd/homexdr-server && \
    mkdir -p /out/downloads /out/data && cd /src/agent && \
    for target in linux/amd64 linux/arm64 windows/amd64; do \
      os=${target%/*}; arch=${target#*/}; ext=""; [ "$os" = windows ] && ext=.exe; \
      GOOS=$os GOARCH=$arch go build -trimpath -ldflags "$LDFLAGS" \
        -o /out/downloads/homexdr-agent-$os-$arch$ext ./cmd/homexdr-agent || exit 1; \
    done && \
    cd /out/downloads && sha256sum homexdr-agent-* > SHA256SUMS

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/homexdr-server /usr/local/bin/homexdr-server
COPY --from=build /out/downloads/ /usr/share/homexdr/downloads/
COPY rules/ /usr/share/homexdr/rules/
COPY --from=build --chown=65532:65532 /out/data /data
ENV HOMEXDR_DATA_DIR=/data \
    HOMEXDR_RULES_DIR=/usr/share/homexdr/rules \
    HOMEXDR_DOWNLOADS_DIR=/usr/share/homexdr/downloads \
    HOMEXDR_HTTP_ADDR=:8080 \
    HOMEXDR_AGENT_ADDR=:8443 \
    HOMEXDR_SYSLOG_ADDR=:5514
EXPOSE 8080/tcp 8443/tcp 5514/udp 5514/tcp
VOLUME /data
USER 65532:65532
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD ["/usr/local/bin/homexdr-server", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/homexdr-server"]
CMD ["serve"]
