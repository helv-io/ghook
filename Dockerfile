# syntax=docker/dockerfile:1

ARG GO_VERSION=1.26.0

FROM golang:${GO_VERSION}-alpine AS build
WORKDIR /src
RUN apk add --no-cache ca-certificates
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/ghook ./cmd/ghook
RUN mkdir -p /out/data

FROM gcr.io/distroless/static-debian12:nonroot
LABEL org.opencontainers.image.title="ghook" \
      org.opencontainers.image.description="Self-hosted Gmail push router. One watch, routes, webhooks." \
      org.opencontainers.image.source="https://github.com/helv-io/ghook"
COPY --from=build /out/ghook /ghook
COPY --from=build --chown=1000:1000 /out/data /data
# Start as root so a fresh volume can be chowned to PUID:PGID, then ghook drops privileges
# before it serves. A container started with user: skips both steps.
ENV DB_PATH=/data/ghook.db LISTEN_ADDR=:8080
VOLUME /data
EXPOSE 8080
USER 0:0
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD ["/ghook", "healthcheck"]
ENTRYPOINT ["/ghook"]
