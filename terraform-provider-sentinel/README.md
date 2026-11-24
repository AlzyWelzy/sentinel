# terraform-provider-sentinel

Sentinel server monitoring as code: alert rules, checks (on your servers or
from the probes), maintenance windows, status pages and agent install keys,
plus a `sentinel_hosts` data source.

## Authenticate

In Sentinel, open **Settings → API tokens** and create a token with
read-only **off**, then:

```sh
export SENTINEL_TOKEN=pgt_...
# Only for a self-hosted Sentinel (the default is https://sentinel.rajpoot.app/api):
export SENTINEL_API_URL=https://<your host>/api
```

A token acts in the organisation it was made in. It can't manage members
or other tokens.

## Resources

| Resource | Notes |
|---|---|
| `sentinel_check` | `type` = tcp, http, tls, dns, ping, file, log. `on_probes = true` for uptime checks from the probe locations. Creates no alert rule by itself. |
| `sentinel_alert_rule` | `kind` = metric, host_down, process_down, service_down, container_down, plugin_down, custom, check, anomaly, forecast. For a check, `kind = "check"` and `target = sentinel_check.x.id`. |
| `sentinel_maintenance_window` | `schedule` = once (`starts_at`/`ends_at`, RFC 3339) or weekly (`weekdays`, `start_time`, `duration_minutes`, `timezone`). |
| `sentinel_status_page` | `items` in display order, each with `host_id` or `check_id`. |
| `sentinel_install_key` | `key`, `install_command`, `cloud_init` are sensitive outputs. Destroy revokes the key; installed servers keep reporting. |

All resources support `terraform import <address> <id>`.

## Data sources

`sentinel_hosts` — servers, filtered by `tag` and/or `hostname`.

See [examples/main.tf](examples/main.tf).

## Install

Releases are on GitHub (`terraform-v*` tags), built for Linux, macOS,
Windows and FreeBSD, with `SHA256SUMS` (signed once a release key is set
up). Until the provider is on the Terraform Registry, use a filesystem
mirror:

```sh
v=0.1.0; os=darwin; arch=arm64   # or linux/amd64, windows/amd64 …
d=~/.terraform.d/plugins/registry.terraform.io/alzywelzy/sentinel/$v/${os}_$arch
mkdir -p "$d" && cd "$d"
curl -fsSLO https://github.com/AlzyWelzy/sentinel/releases/download/terraform-v$v/terraform-provider-sentinel_${v}_${os}_$arch.zip
unzip -o terraform-provider-sentinel_${v}_${os}_$arch.zip && rm terraform-provider-sentinel_*.zip
```

```hcl
terraform {
  required_providers {
    sentinel = { source = "alzywelzy/sentinel", version = "~> 0.1" }
  }
}
provider "sentinel" {}
```

The same works with OpenTofu (`~/.terraform.d/plugins` is read by both).

## Build and use locally


```sh
go build -o ~/.terraform.d/plugins/terraform-provider-sentinel .
cat >> ~/.terraformrc <<'RC'
provider_installation {
  dev_overrides { "alzywelzy/sentinel" = "/Users/<you>/.terraform.d/plugins" }
  direct {}
}
RC
```
