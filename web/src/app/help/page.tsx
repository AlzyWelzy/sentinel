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

      <h2>4. Work as a team</h2>
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
