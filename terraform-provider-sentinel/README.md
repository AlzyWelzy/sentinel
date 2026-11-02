# terraform-provider-sentinel

Sentinel server monitoring as code: alert rules, checks (on your servers or
from the probes), maintenance windows, status pages and agent install keys,
plus a `sentinel_hosts` data source.

## Authenticate

Create an API token in the console (Monitoring → Servers → API) with
read-only **off**, then:

```sh
export SENTINEL_API_URL=https://<console host>/api/sentinel
export SENTINEL_TOKEN=pgt_...
```

Tokens act as the account that made them. They can't manage team members or
other tokens.

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
