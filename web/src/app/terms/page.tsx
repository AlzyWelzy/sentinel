import type { Metadata } from "next";

import { Prose } from "@/components/site";

export const metadata: Metadata = { title: "Terms" };

export default function Terms() {
  return (
    <Prose title="Terms of service" updated="2 November 2026">
      <p>
        These terms apply to your use of Sentinel at sentinel.rajpoot.app. By creating an account
        you agree to them. Contact: <a href="mailto:ops@rajpoot.app">ops@rajpoot.app</a>.
      </p>
      <h2>Your account</h2>
      <ul>
        <li>
          Give a real email address you control, keep your password private, and turn on two-factor
          sign-in.
        </li>
        <li>
          You&apos;re responsible for what happens in your account and the organisations you own.
        </li>
        <li>You must be old enough to agree to these terms where you live.</li>
      </ul>
      <h2>Acceptable use</h2>
      <ul>
        <li>Only monitor servers and websites you own or are allowed to monitor.</li>
        <li>
          Don&apos;t use uptime checks or webhooks to attack, scan or overload anyone, and
          don&apos;t try to reach other organisations&apos; data or get around limits.
        </li>
        <li>Don&apos;t send unlawful content, malware or spam through the service.</li>
      </ul>
      <p>
        We may suspend organisations that break these rules or put the service at risk, and will
        tell the owner why.
      </p>
      <h2>Your data</h2>
      <p>
        Your monitoring data and configuration stay yours. You give us permission to store and
        process them only to run the service for you, as described in the{" "}
        <a href="/privacy">privacy policy</a>. You can export and delete them at any time.
      </p>
      <h2>The service</h2>
      <p>
        We work to keep Sentinel available and accurate, and run it with backups and monitoring of
        its own. It&apos;s provided as is, without a guaranteed level of availability: alerts can be
        delayed or missed (for example when an email provider is down), so don&apos;t rely on
        Sentinel as your only safeguard for safety-critical systems.
      </p>
      <h2>Liability</h2>
      <p>
        To the extent the law allows, we aren&apos;t liable for indirect or consequential losses, or
        for losses caused by alerts that were late or didn&apos;t arrive. Nothing here limits
        liability that can&apos;t be limited by law.
      </p>
      <h2>Ending</h2>
      <p>
        You can stop at any time by deleting your organisations and account. We may end the service
        with 30 days&apos; notice by email, giving you time to export your data.
      </p>
      <h2>Changes</h2>
      <p>
        We&apos;ll update the date above and email account owners about significant changes before
        they apply. Continuing to use Sentinel after that means you accept them.
      </p>
    </Prose>
  );
}
