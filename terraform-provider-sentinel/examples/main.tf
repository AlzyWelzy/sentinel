terraform {
  required_providers {
    sentinel = { source = "alzywelzy/sentinel" }
  }
}

provider "sentinel" {
  api_url = "https://<console host>/api/sentinel" # or SENTINEL_API_URL
}

data "sentinel_hosts" "web" {
  tag = "web"
}

resource "sentinel_check" "site" {
  name             = "website"
  type             = "http"
  target           = "https://example.com/"
  on_probes        = true
  min_failing      = 1
  interval_seconds = 60
  params           = { expect_status = "200-399", tls_expiry_days = "14" }
}

resource "sentinel_alert_rule" "site_down" {
  name     = "website down"
  kind     = "check"
  target   = sentinel_check.site.id
  severity = "critical"
  description = "Check the web servers and the load balancer."
}

resource "sentinel_alert_rule" "cpu" {
  name        = "high CPU on web"
  kind        = "metric"
  metric      = "cpu"
  operator    = ">"
  threshold   = var.cpu_threshold
  aggregation = "avg"
  window_seconds     = 600
  duration_seconds   = 300
  recovery_threshold = 70
  tag         = "web"
  severity    = "warning"
}

resource "sentinel_maintenance_window" "patching" {
  name             = "Sunday patching"
  tag              = "web"
  schedule         = "weekly"
  weekdays         = [7]
  start_time       = "02:00"
  duration_minutes = 60
  timezone         = "Asia/Kolkata"
}

resource "sentinel_maintenance_window" "once" {
  name      = "migration"
  schedule  = "once"
  starts_at = "2026-12-01T22:00:00Z"
  ends_at   = "2026-12-01T23:30:00Z"
}

resource "sentinel_status_page" "public" {
  slug  = "acme-status"
  title = "Acme status"
  items = concat(
    [{ label = "Website", check_id = sentinel_check.site.id, host_id = null }],
    [for h in data.sentinel_hosts.web.hosts : { label = "Server ${h.hostname}", host_id = h.id, check_id = null }]
  )
}

resource "sentinel_install_key" "ci" {
  name = "autoscaling group"
  tags = ["web", "terraform"]
}

variable "cpu_threshold" {
  type    = number
  default = 90
}

output "web_hosts" { value = [for h in data.sentinel_hosts.web.hosts : h.hostname] }
output "status_url_slug" { value = sentinel_status_page.public.slug }
