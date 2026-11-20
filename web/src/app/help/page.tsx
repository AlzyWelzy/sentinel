import type { Metadata } from "next";

import { Prose } from "@/components/site";

export const metadata: Metadata = { title: "Guide" };

export default function Help() {
  return (
    <Prose title="Guide">
      <p>
        Everything you need to go from sign-up to your first alert, and what to do when something
        looks off.
      </p>

      <h2>1. Add a server</h2>
      <p>
        Open <b>Add server</b> and create an install key. Run the command it shows on the server. As
        root it installs directly; as another user it asks for sudo (or doas):
      </p>
      <pre>
        curl -fsSL https://get.sentinel.rajpoot.app/install.sh | sh -s -- --key pg_… --tags
        web,production
      </pre>
      <ul>
        <li>
          FreeBSD without curl: <code>fetch -qo - … | sh -s -- …</code>. OpenBSD:{" "}
          <code>ftp -o - … | sh -s -- …</code>.
        </li>
        <li>
          Windows (Server 2016+, 10+): run the PowerShell command from the page in an elevated
          PowerShell.
        </li>
        <li>Docker, Kubernetes and cloud-init have their own snippets on the same page.</li>
      </ul>
      <p>
        The server appears within a minute. The agent runs as an unprivileged <code>sentinel</code>{" "}
        user, keeps 24 hours of data on disk if the network drops, and updates itself hourly.
      </p>

      <h2>2. Get alerted</h2>
      <p>
        Every organisation starts with recommended rules: server not reporting, high CPU and memory,
        disks filling up. Add your own under <b>Alert rules</b>; <b>Preview last 7 days</b> shows
        how often a rule would have fired before you save it. Alerts go to the organisation&apos;s
        email by default. Add Slack, Teams, Discord, Telegram, PagerDuty, webhooks or browser push
        under <b>Contacts</b>; new contacts are verified first.
      </p>
      <ul>
        <li>
          <b>Quiet hours</b> per contact (critical alerts can still come through), and the lowest
          severity it receives.
        </li>
        <li>
          <b>On-call</b> rotations: rules page whoever is on call, and <b>escalation steps</b>{" "}
          notify more people while nobody acknowledges.
        </li>
        <li>
          <b>Maintenance windows</b> hold alerts back while you work; <b>Depends on</b> (server
          Settings tab) holds a server&apos;s alerts while the server it depends on is down.
        </li>
      </ul>

      <h2>3. Watch websites</h2>
      <p>
        <b>Uptime checks</b> test URLs, ports, TLS certificates and DNS from probe locations. Add a
        check to a <b>status page</b> to show its uptime publicly, under a name you choose.
      </p>

      <h2>4. Monitor the network</h2>
      <p>
        Switches, firewalls and Proxmox clusters are polled by one of your servers on the same
        network, so install the agent there first.
      </p>
      <ul>
        <li>
          Under <b>Network › Credentials</b>, add the read-only SNMP community (v2c) or SNMPv3 user
          your devices use, or a Proxmox API token (the PVEAuditor role is enough).
        </li>
        <li>
          <b>Add devices</b> by address, or <b>Discover</b> a private range (up to /22) and pick
          what it finds. The server must reach the devices on UDP 161 (Proxmox: TCP 8006). A scan
          that doesn&apos;t start within 10 minutes means the server isn&apos;t reporting.
        </li>
        <li>
          Mark your core switch(es) with the role <i>Core</i>: upstreams are worked out from LLDP,
          so when a switch fails the devices behind it are shown as affected instead of each
          alerting. Servers whose network cards the switch sees over LLDP depend on it too.
        </li>
        <li>
          Network alert rules (interfaces down, busy or with errors, and each vendor&apos;s own) are
          added with your first device. Give customer ports a billing tag to see their
          95th-percentile bandwidth.
        </li>
      </ul>

      <h2>5. Work as a team</h2>
      <p>
        Invite people under <b>Organisation</b>. Admins change anything except API tokens and
        deleting the organisation; members acknowledge and resolve incidents and schedule
        maintenance; read-only members look. Every change is in the <b>Audit log</b>.
      </p>

      <h2>Services, logs and traces</h2>
      <ul>
        <li>
          Plugins (MySQL, PostgreSQL, Redis, Nginx, Apache, Docker, SMART, IPMI, SNMP, Prometheus,
          scripts) are configured on the server in <code>/etc/sentinel/plugins.d/</code>; the
          installer sets up the ones it detects. Test them with <code>sentinel-agent plugins</code>.
        </li>
        <li>
          Logs: the installer turns on <code>/var/log</code> and the journal; edit{" "}
          <code>/etc/sentinel/logs.conf</code> to change what&apos;s sent.
        </li>
        <li>
          Traces: point your app&apos;s OpenTelemetry exporter at <code>http://localhost:4318</code>
          .
        </li>
      </ul>

      <h2>Troubleshooting</h2>
      <h3>The server doesn&apos;t appear</h3>
      <ul>
        <li>
          Linux: <code>systemctl status sentinel-agent</code> and{" "}
          <code>journalctl -u sentinel-agent -n 50</code>.
        </li>
        <li>
          Windows: check the <i>Sentinel agent</i> service is running (
          <code>Get-Service sentinel-agent</code>). To watch its output, stop the service and run{" "}
          <code>
            &amp; &quot;$env:ProgramFiles\Sentinel\sentinel-agent.exe&quot; run --state-dir
            &quot;$env:ProgramData\Sentinel&quot;
          </code>{" "}
          in an elevated PowerShell, then start the service again.
        </li>
        <li>
          The server must reach <code>ingest.sentinel.rajpoot.app</code> on port 443. Behind a
          proxy, set <code>HTTPS_PROXY</code> for the service.
        </li>
      </ul>
      <h3>A network device says &ldquo;No SNMP answer&rdquo;</h3>
      <ul>
        <li>
          From the polling server: <code>snmpget -v2c -c COMMUNITY ADDRESS 1.3.6.1.2.1.1.5.0</code>.
          No answer means a firewall in between, SNMP off on the device, or a device allow-list that
          doesn&apos;t include the server.
        </li>
        <li>
          An answer there but not in Sentinel: check the credential on the device&apos;s page.
        </li>
      </ul>
      <h3>An alert didn&apos;t arrive</h3>
      <p>
        The incident page shows each notification and whether it was delivered. A contact marked{" "}
        <b>bounced</b> was refused by its mail server: check the address and verify it again.
      </p>
      <h3>Remove the agent</h3>
      <pre>curl -fsSL https://get.sentinel.rajpoot.app/install.sh | sh -s -- --uninstall</pre>
      <p>
        On Windows, run the install command with <code>-Uninstall</code>. The server stays listed
        (as not reporting) until you remove it on its page.
      </p>
      <h2>Still stuck?</h2>
      <p>
        Email <a href="mailto:ops@rajpoot.app">ops@rajpoot.app</a> with your organisation name and
        what you expected to see.
      </p>
    </Prose>
  );
}
