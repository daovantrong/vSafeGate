# Stage 1: Build Caddy with Coraza WAF plugin
FROM caddy:2.8-builder AS builder

RUN xcaddy build \
    --with github.com/corazawaf/coraza-caddy/v2

# Stage 2: Final runtime image
FROM caddy:2.8-alpine

COPY --from=builder /usr/bin/caddy /usr/bin/caddy

# Tạo thư mục chứa rules
RUN mkdir -p /etc/caddy/rules

WORKDIR /etc/caddy
