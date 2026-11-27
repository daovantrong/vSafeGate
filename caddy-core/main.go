package main

import (
	caddycmd "github.com/caddyserver/caddy/v2/cmd"
	_ "github.com/caddyserver/caddy/v2/modules/standard"
	_ "github.com/corazawaf/coraza-caddy/v2"

	_ "caddy-core/modules/cf_dns"
	_ "caddy-core/modules/pre_tls"
	_ "caddy-core/modules/shield"
)

func main() {
	caddycmd.Main()
}
