# Stage 1: Build vendored Caddy with Coraza WAF plugin completely offline (reproducible)
FROM golang:1.27.1-alpine AS builder

WORKDIR /src
COPY caddy-core/ ./

RUN CGO_ENABLED=0 go build -mod=vendor -ldflags="-s -w" -o /usr/bin/caddy .

# Stage 2: Minimal immutable runtime image
FROM alpine:3.21

RUN apk add --no-cache ca-certificates tzdata && \
    mkdir -p /etc/caddy/rules /var/log/caddy /data /config

COPY --from=builder /usr/bin/caddy /usr/bin/caddy

WORKDIR /etc/caddy
EXPOSE 80 443 2019

CMD ["/usr/bin/caddy", "run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]
