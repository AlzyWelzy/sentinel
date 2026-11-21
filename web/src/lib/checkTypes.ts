// What each check type asks for. The API validates the same keys
// (api/app/routes/checks.py PARAMS); this only decides the form.

export type ParamField = {
  key: string;
  label: string;
  kind?: "text" | "password" | "number" | "bool" | "select" | "pem";
  options?: [string, string][];
  placeholder?: string;
  hint?: string;
};

export type CheckType = {
  value: string;
  label: string;
  group: "Web" | "Network" | "Databases and brokers" | "On the server" | "Heartbeat";
  placeholder: string;
  probes: boolean;
  fields: ParamField[];
};

const COMPARE: [string, string][] = [
  ["==", "equals"],
  ["!=", "is not"],
  ["contains", "contains"],
  ["not_contains", "doesn't contain"],
  [">", ">"],
  [">=", "≥"],
  ["<", "<"],
  ["<=", "≤"],
];
const TLS: ParamField[] = [
  { key: "tls", label: "Use TLS", kind: "bool" },
  { key: "tls_skip_verify", label: "Accept any certificate", kind: "bool" },
];

export const CHECK_TYPES: CheckType[] = [
  {
    value: "group",
    label: "Group of checks",
    group: "Heartbeat",
    placeholder: "",
    probes: false,
    fields: [],
  },
  {
    value: "push",
    label: "Push (heartbeat URL)",
    group: "Heartbeat",
    placeholder: "",
    probes: false,
    fields: [
      {
        key: "grace_seconds",
        label: "Grace (seconds)",
        kind: "number",
        hint: "Extra wait after a missed push before alerting",
      },
    ],
  },
  {
    value: "http",
    label: "HTTP(S)",
    group: "Web",
    placeholder: "https://example.com/health",
    probes: true,
    fields: [
      {
        key: "method",
        label: "Method",
        kind: "select",
        options: ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"].map((m) => [m, m]),
      },
      { key: "expect_status", label: "Expected status", placeholder: "200-399" },
      { key: "keyword", label: "Page must contain", placeholder: "Welcome" },
      { key: "keyword_absent", label: "…must not contain it instead", kind: "bool" },
      { key: "keyword_case_insensitive", label: "Ignore case", kind: "bool" },
      { key: "json_path", label: "JSON value", placeholder: "status.db" },
      { key: "json_op", label: "Comparison", kind: "select", options: COMPARE },
      { key: "json_expect", label: "Expected value", placeholder: "UP" },
      { key: "headers", label: "Headers (JSON)", placeholder: '{"X-Env": "prod"}' },
      { key: "body", label: "Body" },
      {
        key: "body_encoding",
        label: "Body type",
        kind: "select",
        options: [
          ["json", "JSON"],
          ["form", "Form"],
          ["xml", "XML"],
        ],
      },
      { key: "basic_user", label: "Basic auth user" },
      { key: "basic_password", label: "Basic auth password", kind: "password" },
      { key: "bearer_token", label: "Bearer token", kind: "password" },
      {
        key: "oauth_token_url",
        label: "OAuth token URL",
        placeholder: "https://login.example.com/oauth/token",
        hint: "Client credentials: a token is fetched and reused until it expires",
      },
      { key: "oauth_client_id", label: "OAuth client ID" },
      { key: "oauth_client_secret", label: "OAuth client secret", kind: "password" },
      { key: "oauth_scopes", label: "OAuth scopes", placeholder: "read:health" },
      {
        key: "oauth_auth_method",
        label: "Send the client secret",
        kind: "select",
        options: [
          ["basic", "As basic auth"],
          ["post", "In the form body"],
        ],
      },
      {
        key: "proxy",
        label: "Proxy",
        placeholder: "http://proxy:3128 or socks5://proxy:1080",
      },
      { key: "client_cert", label: "Client certificate (PEM)", kind: "pem" },
      { key: "client_key", label: "Client key (PEM)", kind: "pem" },
      { key: "tls_expiry_days", label: "Warn days before the certificate expires", kind: "number" },
      { key: "max_redirects", label: "Most redirects", kind: "number" },
      { key: "tls_skip_verify", label: "Accept any certificate", kind: "bool" },
      { key: "cache_bust", label: "Bypass caches", kind: "bool" },
    ],
  },
  {
    value: "websocket",
    label: "WebSocket",
    group: "Web",
    placeholder: "wss://example.com/socket",
    probes: true,
    fields: [
      { key: "subprotocol", label: "Subprotocol" },
      { key: "tls_skip_verify", label: "Accept any certificate", kind: "bool" },
    ],
  },
  {
    value: "tls",
    label: "TLS certificate",
    group: "Web",
    placeholder: "example.com:443",
    probes: true,
    fields: [{ key: "tls_expiry_days", label: "Warn days before expiry", kind: "number" }],
  },
  {
    value: "grpc",
    label: "gRPC health",
    group: "Web",
    placeholder: "api.example.com:443",
    probes: true,
    fields: [
      { key: "service", label: "Service", hint: "Empty checks the whole server" },
      { key: "metadata", label: "Metadata (JSON)" },
      ...TLS,
    ],
  },
  {
    value: "tcp",
    label: "TCP port",
    group: "Network",
    placeholder: "example.com:22",
    probes: true,
    fields: [],
  },
  {
    value: "ping",
    label: "Ping",
    group: "Network",
    placeholder: "example.com",
    probes: true,
    fields: [],
  },
  {
    value: "dns",
    label: "DNS record",
    group: "Network",
    placeholder: "example.com",
    probes: true,
    fields: [
      {
        key: "record_type",
        label: "Record",
        kind: "select",
        options: ["A", "AAAA", "CNAME", "MX", "NS", "TXT"].map((m) => [m, m]),
      },
      { key: "expect", label: "Expected answer" },
      { key: "server", label: "DNS server", placeholder: "1.1.1.1" },
    ],
  },
  {
    value: "smtp",
    label: "SMTP",
    group: "Network",
    placeholder: "mail.example.com:587",
    probes: true,
    fields: [
      {
        key: "security",
        label: "Security",
        kind: "select",
        options: [
          ["none", "None"],
          ["starttls", "STARTTLS"],
          ["tls", "TLS"],
        ],
      },
      { key: "tls_skip_verify", label: "Accept any certificate", kind: "bool" },
    ],
  },
  {
    value: "ntp",
    label: "NTP",
    group: "Network",
    placeholder: "pool.ntp.org",
    probes: true,
    fields: [
      { key: "max_offset_ms", label: "Largest clock offset (ms)", kind: "number" },
      { key: "max_stratum", label: "Highest stratum", kind: "number" },
    ],
  },
  {
    value: "sip",
    label: "SIP (VoIP)",
    group: "Network",
    placeholder: "pbx.example.com:5060",
    probes: true,
    fields: [],
  },
  {
    value: "radius",
    label: "RADIUS",
    group: "Network",
    placeholder: "aaa.example.com:1812",
    probes: true,
    fields: [
      { key: "secret", label: "Shared secret", kind: "password" },
      { key: "username", label: "User" },
      { key: "password", label: "Password", kind: "password" },
      { key: "called_station_id", label: "Called-Station-Id" },
      { key: "calling_station_id", label: "Calling-Station-Id" },
    ],
  },
  {
    value: "snmp",
    label: "SNMP value",
    group: "Network",
    placeholder: "10.0.0.1",
    probes: true,
    fields: [
      { key: "oid", label: "OID", placeholder: "1.3.6.1.2.1.1.3.0" },
      { key: "community", label: "Community", kind: "password", placeholder: "public" },
      {
        key: "version",
        label: "Version",
        kind: "select",
        options: [
          ["2c", "v2c"],
          ["1", "v1"],
        ],
      },
      { key: "op", label: "Comparison", kind: "select", options: COMPARE },
      { key: "expect", label: "Expected value" },
    ],
  },
  {
    value: "game",
    label: "Game server",
    group: "Network",
    placeholder: "play.example.com:27015",
    probes: true,
    fields: [
      {
        key: "protocol",
        label: "Game",
        kind: "select",
        options: [
          ["a2s", "Source / Steam"],
          ["minecraft", "Minecraft (Java)"],
        ],
      },
    ],
  },
  {
    value: "postgres",
    label: "PostgreSQL",
    group: "Databases and brokers",
    placeholder: "postgres://user:password@db.example.com:5432/app",
    probes: true,
    fields: [
      { key: "query", label: "Query", placeholder: "SELECT 1" },
      { key: "expect", label: "Expected result" },
    ],
  },
  {
    value: "mysql",
    label: "MySQL / MariaDB",
    group: "Databases and brokers",
    placeholder: "mysql://user:password@db.example.com:3306/app",
    probes: true,
    fields: [
      { key: "query", label: "Query", placeholder: "SELECT 1" },
      { key: "expect", label: "Expected result" },
      { key: "tls_skip_verify", label: "Accept any certificate", kind: "bool" },
    ],
  },
  {
    value: "redis",
    label: "Redis",
    group: "Databases and brokers",
    placeholder: "redis://:password@cache.example.com:6379/0",
    probes: true,
    fields: [{ key: "tls_skip_verify", label: "Accept any certificate", kind: "bool" }],
  },
  {
    value: "mongodb",
    label: "MongoDB",
    group: "Databases and brokers",
    placeholder: "db.example.com:27017",
    probes: true,
    fields: TLS,
  },
  {
    value: "kafka",
    label: "Kafka broker",
    group: "Databases and brokers",
    placeholder: "broker.example.com:9092",
    probes: true,
    fields: TLS,
  },
  {
    value: "mqtt",
    label: "MQTT",
    group: "Databases and brokers",
    placeholder: "mqtt.example.com:1883",
    probes: true,
    fields: [
      { key: "topic", label: "Topic to wait on", hint: "Empty only checks the connection" },
      { key: "expect", label: "Message must contain" },
      { key: "username", label: "User" },
      { key: "password", label: "Password", kind: "password" },
      ...TLS,
    ],
  },
  {
    value: "docker",
    label: "Docker container",
    group: "On the server",
    placeholder: "web",
    probes: false,
    fields: [{ key: "socket", label: "Docker socket", placeholder: "/var/run/docker.sock" }],
  },
  {
    value: "service",
    label: "System service",
    group: "On the server",
    placeholder: "nginx",
    probes: false,
    fields: [],
  },
  {
    value: "file",
    label: "File",
    group: "On the server",
    placeholder: "/var/backups/db.sql.gz",
    probes: false,
    fields: [
      {
        key: "mode",
        label: "Condition",
        kind: "select",
        options: [
          ["exists", "exists"],
          ["absent", "is absent"],
          ["changed", "changed"],
          ["max_age_seconds", "is newer than (seconds)"],
          ["max_size_bytes", "is smaller than (bytes)"],
        ],
      },
      { key: "value", label: "Value" },
    ],
  },
  {
    value: "log",
    label: "Log pattern",
    group: "On the server",
    placeholder: "/var/log/app.log",
    probes: false,
    fields: [
      { key: "pattern", label: "Pattern (regular expression)", placeholder: "(?i)fatal" },
      { key: "threshold", label: "Matches before alerting", kind: "number" },
    ],
  },
];

export const checkType = (v: string) =>
  CHECK_TYPES.find((t) => t.value === v) ?? (CHECK_TYPES[0] as CheckType);
