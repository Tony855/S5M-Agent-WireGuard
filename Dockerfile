# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM golang:1.23-bookworm AS build

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" \
    -o /out/wg-agent ./cmd/wg-agent

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates iproute2 wireguard-tools \
    && rm -rf /var/lib/apt/lists/* \
    && install -d -m 0700 /data

COPY --from=build /out/wg-agent /usr/local/bin/wg-agent

ENV WG_DATA_DIR=/data
VOLUME ["/data"]
EXPOSE 51820/udp

ENTRYPOINT ["/usr/local/bin/wg-agent"]
CMD ["agent-run", "--agent-config", "/data/agent.yaml", "--data-dir", "/data", "--config", "/data/config.yaml"]
