import type { Metadata } from "next";

import { Prose } from "@/components/site";

export const metadata: Metadata = { title: "Privacy" };

export default function Privacy() {
  return (
    <Prose title="Privacy policy" updated="2 November 2026">
      <p>
        This policy explains what Sentinel (sentinel.rajpoot.app, &quot;we&quot;) collects, why, how
        long it&apos;s kept and what you can do about it. Questions:{" "}
        <a href="mailto:ops@rajpoot.app">ops@rajpoot.app</a>.
      </p>
      <h2>What we collect</h2>
      <ul>
        <li>
          <b>Your account:</b> email address, name if you give one, a password hash (argon2id; we
          never see or store the password), two-factor secret (encrypted), and the browsers
          you&apos;re signed in from (IP address and browser name).
        </li>
        <li>
          <b>Your organisation:</b> its name, members and their roles, alert rules, contacts (email
          addresses, webhook and chat URLs, phone numbers if you add them), status pages and an
          audit log of changes.
        </li>
        <li>
          <b>Monitoring data the agent sends:</b> resource metrics, process and service names,
          installed packages, IP addresses, hostnames, log lines from the files you allow, and
          traces your apps send to it. The agent only reads what its configuration on your server
          allows.
        </li>
        <li>
          <b>Request logs:</b> IP address, time and path of requests to the service, kept to keep it
          secure and running.
        </li>
      </ul>
      <p>
        We don&apos;t use advertising or analytics trackers, and we don&apos;t sell or share your
        data for marketing.
      </p>
      <h2>Why</h2>
      <p>
        To provide the service you signed up for: store and chart your data, evaluate your alert
        rules, send the notifications you configured, and keep accounts secure (rate limits,
        captcha, lockouts). The legal basis is the contract with you, and our legitimate interest in
        security.
      </p>
      <h2>Who else processes it</h2>
      <ul>
        <li>Our hosting provider, where the service and its databases run.</li>
        <li>Our email provider, which delivers account and alert emails.</li>
        <li>Cloudflare Turnstile, which checks sign-up and password-reset forms for bots.</li>
        <li>
          The services you connect yourself (Slack, Microsoft Teams, Discord, Telegram, PagerDuty,
          webhooks, Web Push), which receive the alerts you route to them.
        </li>
      </ul>
      <h2>How long we keep it</h2>
      <ul>
        <li>Raw metrics: 90 days. Hourly summaries: 2 years. Logs: 14 days. Traces: 7 days.</li>
        <li>
          Incidents, rules, audit log and account data: as long as your organisation or account
          exists.
        </li>
        <li>Database backups: 7 days, after which deleted data is gone from them too.</li>
      </ul>
      <h2>Your rights</h2>
      <ul>
        <li>
          <b>Export:</b> owners and admins download everything an organisation has as JSON
          (Organisation → Your data).
        </li>
        <li>
          <b>Deletion:</b> owners delete an organisation and all its data (Organisation → Delete).
          You delete your account under Your account; organisations only you are in are deleted with
          it.
        </li>
        <li>
          <b>Correction:</b> change your name and password in Your account. For anything else, or to
          object to processing, email us.
        </li>
      </ul>
      <h2>Security</h2>
      <p>
        Data travels over TLS. Every organisation&apos;s data is isolated in the database itself,
        not only in our code. Superadmins can look inside an organisation only to help with a
        problem, for at most an hour at a time, and every such visit is recorded.
      </p>
      <h2>Changes</h2>
      <p>We&apos;ll update the date above and email account owners about significant changes.</p>
    </Prose>
  );
}
