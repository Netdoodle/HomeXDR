# syntax=docker/dockerfile:1
# HomeXDR YARA scanner (docs/antivirus.md): homexdr-yara plus the yara and yarac tools.
# Build from the repository root:  docker build -f deploy/yara/Dockerfile -t homexdr/yara .

FROM golang:1.27-alpine AS build
WORKDIR /src
ENV CGO_ENABLED=0
COPY shared/ shared/
COPY server/go.mod server/go.sum server/
RUN cd server && go mod download
COPY server/ server/
RUN cd server && go build -trimpath -ldflags "-s -w" -o /out/homexdr-yara ./cmd/homexdr-yara

FROM alpine:3.22
RUN apk add --no-cache yara ca-certificates && \
    adduser -D -H -u 10001 yara && \
    mkdir -p /var/lib/homexdr-yara /rules && chown yara:yara /var/lib/homexdr-yara
COPY --from=build /out/homexdr-yara /usr/local/bin/homexdr-yara
VOLUME /var/lib/homexdr-yara
USER 10001:10001
EXPOSE 3320/tcp
# The first start downloads and compiles the rule package, about a minute.
HEALTHCHECK --interval=30s --timeout=5s --start-period=180s --retries=3 \
  CMD ["/usr/local/bin/homexdr-yara", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/homexdr-yara"]
