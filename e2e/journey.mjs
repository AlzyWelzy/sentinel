// End-to-end journey through the real web app, behind Caddy, against the
// real API, ingest, alerter and a real agent. Fails on any page error or
// console error. Screenshots go to ./shots for review.
import { execFileSync, spawn } from "node:child_process";
import { createHmac } from "node:crypto";
import { mkdirSync, rmSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { chromium } from "playwright";

const BASE = process.env.BASE ?? "http://localhost:3000";
const MAILPIT = "http://localhost:8035";
const REPO = fileURLToPath(new URL("..", import.meta.url));
const STATE = `${REPO}/.agent/state`;
const run = Date.now().toString(36);
const owner = { name: "Olivia Owner", email: `owner-${run}@example.com`, password: "owner password 123" };
const member = { name: "Max Member", email: `member-${run}@example.com`, password: "member password 123" };
const admin = { name: "Ada Admin", email: "admin@sentinel.test", password: "admin password 123" };

mkdirSync("shots", { recursive: true });
const errors = [];
let step = 0;
const log = (m) => console.log(`[${new Date().toISOString().slice(11, 19)}] ${++step}. ${m}`);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function watch(page, who) {
  page.on("pageerror", (e) => errors.push(`${who} pageerror: ${e.message}`));
  page.on("console", (m) => {
    if (m.type() === "error" && !/Failed to load resource: the server responded with a status of (401|403|404|409)/.test(m.text()))
      errors.push(`${who} console: ${m.text()}`);
  });
}

async function shot(page, name) {
  await page.waitForLoadState("networkidle").catch(() => {});
  await page.screenshot({ path: `shots/${String(step).padStart(2, "0")}-${name}.png`, fullPage: true });
}

async function mailLink(to, path, { after = 0 } = {}) {
  for (let i = 0; i < 60; i++) {
    const r = await fetch(`${MAILPIT}/api/v1/search?query=${encodeURIComponent(`to:${to}`)}`).then((r) => r.json());
    for (const m of r.messages) {
      if (Date.parse(m.Created) < after) continue;
      const msg = await fetch(`${MAILPIT}/api/v1/message/${m.ID}`).then((r) => r.json());
      const match = msg.Text.match(new RegExp(`(https?://[^\\s]+${path}\\?token=[A-Za-z0-9_%-]+)`));
      if (match) return match[1].replace(/^https?:\/\/[^/]+/, BASE);
    }
    await sleep(1000);
  }
  throw new Error(`no ${path} email for ${to}`);
}

async function subjects(to) {
  const r = await fetch(`${MAILPIT}/api/v1/search?query=${encodeURIComponent(`to:${to}`)}`).then((r) => r.json());
  return r.messages.map((m) => m.Subject);
}

function totp(secret) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const c of secret.replace(/=+$/, "")) bits += alphabet.indexOf(c).toString(2).padStart(5, "0");
  const key = Buffer.from(bits.match(/.{8}/g).map((b) => parseInt(b, 2)));
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000)));
  const h = createHmac("sha1", key).update(counter).digest();
  const o = h[h.length - 1] & 15;
  return String((h.readUInt32BE(o) & 0x7fffffff) % 1e6).padStart(6, "0");
}

async function signUp(page, who) {
  await page.goto(`${BASE}/signup`);
  await page.getByLabel("Name", { exact: true }).fill(who.name);
  await page.getByLabel("Work email").fill(who.email);
  await page.getByLabel("Password").fill(who.password);
  const sentAfter = Date.now() - 2000;
  await page.getByRole("button", { name: "Create account" }).click();
  await page.getByText("Check your email").waitFor();
  await page.goto(await mailLink(who.email, "/verify", { after: sentAfter }));
  await page.waitForURL(/\/(welcome|invitations)/);
}

async function expectText(page, text, timeout = 15000) {
  await page.getByText(text, { exact: false }).first().waitFor({ timeout });
}

let agent;
const browser = await chromium.launch();
try {
  // ── Owner signs up ──────────────────────────────────────────────────────
  const ctx = await browser.newContext({ viewport: { width: 1360, height: 900 } });
  const page = await ctx.newPage();
  watch(page, "owner");
  log("the landing page, legal pages and guide are public and server-rendered");
  for (const [path, text] of [["/", "Know your servers are fine"], ["/terms", "Terms of service"], ["/privacy", "Privacy policy"], ["/help", "Add a server"]]) {
    const html = await fetch(`${BASE}${path}`).then((x) => x.text());
    if (!html.includes(text)) throw new Error(`${path} doesn't render "${text}" on the server`);
  }
  await page.goto(`${BASE}/`);
  await shot(page, "landing");
  log("the dashboard needs sign-in");
  await page.goto(`${BASE}/overview`);
  await page.waitForURL(/\/login\?next=/);
  await shot(page, "login");

  log("sign up, confirm by the emailed link, land on onboarding");
  await signUp(page, owner);
  await shot(page, "welcome");

  log("reload keeps the session (refresh cookie reaches /api/auth)");
  await page.reload();
  await expectText(page, "Add a server");

  log("name the organisation");
  await page.getByLabel("Organisation name").fill("Acme Robotics");
  await page.getByRole("button", { name: "Save" }).click();
  await expectText(page, "Currently: Acme Robotics");

  log("create an install key and read the install command");
  await page.getByRole("button", { name: "Create install key" }).click();
  const command = await page.locator("pre").first().innerText();
  const key = command.match(/--key (pg_[A-Za-z0-9_-]+)/)?.[1];
  if (!key) throw new Error(`no key in install command: ${command}`);
  if (!command.includes("get.") && !command.includes("localhost")) throw new Error(command);
  await shot(page, "install-command");

  log("install.sh is served and has the URLs filled in");
  const sh = await fetch(`${BASE}/api/install.sh`).then((r) => r.text());
  if (!sh.includes("sentinel-agent") || sh.includes("__INGEST_URL__")) throw new Error("install.sh not rendered");

  log("a real agent registers and the page sees it arrive");
  rmSync(STATE, { recursive: true, force: true });
  execFileSync(`${REPO}/.agent/sentinel-agent`, ["register", "--url", "http://localhost:8090", "--key", key, "--state-dir", STATE, "--tags", "web,production"]);
  agent = spawn(`${REPO}/.agent/sentinel-agent`, ["run", "--state-dir", STATE], { stdio: "ignore" });
  await expectText(page, "is reporting", 90000);
  await shot(page, "arrived");

  // ── Using the product ───────────────────────────────────────────────────
  log("overview shows the server and the counts");
  await page.goto(`${BASE}/overview`);
  await expectText(page, "Fleet averages");
  await shot(page, "overview");

  log("servers list: search and tag filter");
  await page.goto(`${BASE}/servers`);
  await page.getByPlaceholder("Search hostname, IP, tag…").fill("production");
  await page.locator("tbody tr").first().waitFor();
  await shot(page, "servers");

  log("server detail: every tab renders, charts draw");
  await page.locator("tbody a").first().click();
  await page.waitForURL(/\/servers\/[0-9a-f-]+$/);
  // The agent has pushed only a couple of times yet: reload until a chart has points.
  for (let i = 0; i < 9 && !(await page.locator(".uplot").count()); i++) {
    await sleep(10000);
    await page.reload();
    await sleep(3000);
  }
  await page.locator(".uplot").first().waitFor({ timeout: 10000 });
  await shot(page, "server-overview");
  for (const tab of ["Disks", "Processes", "Network", "System", "Activity"]) {
    await page.getByRole("button", { name: tab, exact: true }).click();
    await sleep(1500);
    await shot(page, `server-${tab.toLowerCase()}`);
  }
  await page.getByRole("button", { name: "Overview", exact: true }).click();
  for (const r of ["15m", "6h", "24h", "7d"]) {
    await page.getByRole("button", { name: r, exact: true }).click();
    await sleep(600);
  }

  log("alert rules: recommended set exists, add one by the form");
  await page.goto(`${BASE}/rules`);
  await expectText(page, "Server not reporting");
  await page.getByRole("button", { name: "New rule" }).click();
  await page.getByLabel("Name", { exact: true }).fill("Load above 50");
  await page.getByLabel("Metric").selectOption("load1");
  await page.getByLabel("Threshold").fill("50");
  await page.getByRole("button", { name: "Create rule" }).click();
  await expectText(page, "Load above 50");
  log("preview a rule over the last 7 days, edit it, send a test alert");
  await page.getByRole("row", { name: /Load above 50/ }).getByRole("button", { name: "Edit" }).click();
  await page.getByRole("button", { name: "Preview last 7 days" }).click();
  await expectText(page, "Over the last 7 days this would have fired");
  await page.getByLabel("Name", { exact: true }).fill("Load above 40");
  await page.getByLabel("Name", { exact: true }).press("Tab");
  await page.getByLabel("Threshold").fill("40");
  await page.getByRole("button", { name: "Save rule" }).click();
  await expectText(page, "Load above 40");
  await page.getByRole("row", { name: /Load above 40/ }).getByRole("button", { name: "Test" }).click();
  await expectText(page, "A test alert was sent");
  await shot(page, "rules");

  log("contacts: the account email is there and verified; add a webhook contact");
  await page.goto(`${BASE}/settings/contacts`);
  await expectText(page, owner.email);
  log("contact settings: warning and up, quiet hours");
  await page.getByRole("button", { name: "Settings" }).first().click();
  await page.getByLabel("Receives").selectOption("warning");
  await page.getByLabel("Quiet hours").check();
  await page.getByRole("button", { name: "Save", exact: true }).click();
  await expectText(page, "Saved.");
  await shot(page, "contacts");
  log("on-call rotation with the owner as responder");
  await page.goto(`${BASE}/oncall`);
  await page.getByLabel("Name", { exact: true }).fill("Primary");
  await page.getByLabel("Responder 1 name").fill("Olivia");
  await page.locator('input[type="checkbox"]').first().check();
  await page.getByRole("button", { name: "Create rotation" }).click();
  await expectText(page, "On call now");
  await expectText(page, "Olivia");
  await shot(page, "oncall");
  await page.goto(`${BASE}/insights`);
  await expectText(page, "Noisy rules");

  log("uptime check and maintenance window");
  await page.goto(`${BASE}/checks`);
  await page.getByLabel("Name", { exact: true }).fill("Example");
  await page.getByLabel("Target").fill("https://example.com");
  await page.getByRole("button", { name: "Add" }).click();
  await expectText(page, "Example");
  await shot(page, "checks");
  await page.goto(`${BASE}/maintenance`);
  await page.getByLabel("Name", { exact: true }).fill("Kernel upgrade");
  await page.getByRole("button", { name: "Schedule" }).click();
  await expectText(page, "Kernel upgrade");
  await page.getByRole("button", { name: "Delete" }).first().click();
  await shot(page, "maintenance");

  log("status page: publish, then the public page renders on the server");
  await page.goto(`${BASE}/status-pages`);
  await page.getByLabel("Title").fill(`Acme status ${run}`);
  await page.locator('input[type="checkbox"]').first().check();
  await page.getByRole("button", { name: "Publish" }).click();
  await expectText(page, "/status/acme-status");
  const slug = `acme-status-${run}`;
  const html = await fetch(`${BASE}/status/${slug}`).then((r) => r.text());
  if (!html.includes(`Acme status ${run}`) || html.includes("ctt.local")) throw new Error("public status page wrong or leaks hostnames");
  const pub = await browser.newPage();
  watch(pub, "public");
  await pub.goto(`${BASE}/status/${slug}`);
  await shot(pub, "public-status");
  await pub.close();

  log("logs, APM, dashboards, reports, audit, tokens all load");
  for (const [path, text] of [
    ["/logs", "Logs"],
    ["/apm", "APM"],
    ["/dashboards", "Dashboards"],
    ["/reports", "Availability"],
    ["/settings/audit", "Audit log"],
    ["/settings/tokens", "Install keys"],
  ]) {
    await page.goto(`${BASE}${path}`);
    await expectText(page, text);
    await shot(page, path.replaceAll("/", "_"));
  }

  log("dashboard with a panel draws a chart");
  await page.goto(`${BASE}/dashboards`);
  await page.getByPlaceholder("New dashboard").fill("Fleet");
  await page.getByRole("button", { name: "Create" }).click();
  await page.getByRole("button", { name: "Add", exact: true }).click();
  await expectText(page, "Remove");
  // A minute-old agent has no complete 75 s step yet: reload until it has.
  for (let i = 0; i < 9 && !(await page.locator(".uplot").count()); i++) {
    await sleep(10000);
    await page.reload();
    await sleep(3000);
  }
  await page.locator(".uplot").first().waitFor({ timeout: 10000 });
  await shot(page, "dashboard");

  log("reports: the PDF downloads");
  await page.goto(`${BASE}/reports`);
  const [download] = await Promise.all([page.waitForEvent("download"), page.getByRole("button", { name: "Download PDF" }).click()]);
  if (!(await download.suggestedFilename()).endsWith(".pdf")) throw new Error("no pdf");

  log("API token: create read-only, it works against the API, then revoke");
  await page.goto(`${BASE}/settings/tokens`);
  await page.getByLabel("Name", { exact: true }).fill("ci");
  await page.getByRole("button", { name: "Create token" }).click();
  const token = (await page.locator("pre").first().innerText()).trim();
  const viaToken = await fetch(`${BASE}/api/v1/hosts`, { headers: { Authorization: `Bearer ${token}` } });
  if (viaToken.status !== 200 || (await viaToken.json()).length !== 1) throw new Error("API token can't read hosts");
  const write = await fetch(`${BASE}/api/v1/agent-keys`, { method: "POST", headers: { Authorization: `Bearer ${token}`, "content-type": "application/json" }, body: '{"name":"x"}' });
  if (write.status !== 403) throw new Error("read-only token could write");

  log("organisation export downloads as JSON without secrets");
  await page.goto(`${BASE}/settings/organisation`);
  const [exp] = await Promise.all([page.waitForEvent("download"), page.getByRole("button", { name: "Download export" }).click()]);
  const exported = JSON.parse(await (await import("node:fs/promises")).readFile(await exp.path(), "utf8"));
  if (exported.format !== "sentinel-export-v1" || !exported.servers.length) throw new Error("bad export");

  // ── Team ────────────────────────────────────────────────────────────────
  log("invite a member; they sign up from the invitation and accept");
  await page.goto(`${BASE}/settings/organisation`);
  await page.getByLabel("Invite by email").fill(member.email);
  await page.getByRole("button", { name: "Send invitation" }).click();
  await expectText(page, `Invitation sent to ${member.email}`);
  const inviteLink = await mailLink(member.email, "/invite");
  const mctx = await browser.newContext({ viewport: { width: 1280, height: 860 } });
  const mpage = await mctx.newPage();
  watch(mpage, "member");
  await mpage.goto(inviteLink);
  await expectText(mpage, "Join Acme Robotics");
  await shot(mpage, "invite");
  log("signing up from the invitation offers it right after confirming the email");
  await signUp(mpage, member);
  await mpage.waitForURL(/\/invitations/);
  await expectText(mpage, "Acme Robotics");
  await shot(mpage, "pending-invitation");
  await mpage.getByRole("button", { name: "Join" }).click();
  await mpage.waitForURL(`${BASE}/overview`);
  await mpage.getByRole("heading", { name: "Acme Robotics" }).waitFor();
  log("the member (operator) can't edit rules");
  await mpage.goto(`${BASE}/rules`);
  await expectText(mpage, "Server not reporting");
  if (await mpage.getByRole("button", { name: "New rule" }).count()) throw new Error("member sees New rule");
  await shot(mpage, "member-rules");

  // ── An outage, end to end ───────────────────────────────────────────────
  log("stop the agent: the not-reporting email arrives and an incident opens");
  const stoppedAt = Date.now();
  agent.kill("SIGTERM");
  let firing = false;
  for (let i = 0; i < 80 && !firing; i++) {
    firing = (await subjects(owner.email)).some((s) => s.includes("FIRING") && s.includes("not reporting"));
    if (!firing) await sleep(5000);
  }
  if (!firing) throw new Error("no FIRING email within 400 s");
  log(`alert email after ${Math.round((Date.now() - stoppedAt) / 1000)} s; the member got it too`);
  if (!(await subjects(member.email)).some((s) => s.includes("FIRING"))) throw new Error("member contact didn't get the alert");

  log("incident page: acknowledge, assign to the member, add a note");
  await page.goto(`${BASE}/incidents`);
  await page.locator("tbody a").first().click();
  await page.getByRole("button", { name: "Acknowledge" }).click();
  await expectText(page, "Acknowledged");
  await page.getByLabel("Assigned to").selectOption({ label: member.name });
  await expectText(page, `Assigned to ${member.name}`);
  await page.getByPlaceholder("Add a note for the team…").fill("Looking into the network");
  await page.getByRole("button", { name: "Add note" }).click();
  await expectText(page, "Looking into the network");
  await page.getByLabel("Snooze escalation").selectOption("60");
  await expectText(page, "snoozed until");
  await expectText(page, "delivered");
  await shot(page, "incident");

  log("start the agent again: recovery email, and the spool's samples arrive");
  agent = spawn(`${REPO}/.agent/sentinel-agent`, ["run", "--state-dir", STATE], { stdio: "ignore" });
  let resolved = false;
  for (let i = 0; i < 40 && !resolved; i++) {
    resolved = (await subjects(owner.email)).some((s) => s.includes("RESOLVED"));
    if (!resolved) await sleep(5000);
  }
  if (!resolved) throw new Error("no RESOLVED email");

  // ── Account security ────────────────────────────────────────────────────
  log("turn on two-factor sign-in");
  await page.goto(`${BASE}/settings`);
  await page.getByRole("button", { name: "Set up" }).click();
  const secret = (await page.locator("p.font-mono").first().innerText()).trim();
  await page.getByLabel("Code").fill(totp(secret));
  await page.getByRole("button", { name: "Turn on" }).click();
  await expectText(page, "Two-factor sign-in is on");
  await expectText(page, "Recovery codes: each signs you in once");
  if ((await page.locator("pre, code").filter({ hasText: /^[0-9a-f]{5}-[0-9a-f]{5}/ }).count()) < 1)
    throw new Error("recovery codes not shown");
  await page.getByRole("button", { name: "I've saved them" }).click();
  await shot(page, "account");

  log("sign out; sign in needs the code");
  await page.getByRole("button", { name: "Sign out" }).click();
  await page.waitForURL(/\/login/);
  await page.getByLabel("Email").fill(owner.email);
  await page.getByLabel("Password").fill(owner.password);
  await page.getByRole("button", { name: "Sign in" }).click();
  await page.getByLabel("Authentication code").fill(totp(secret));
  await page.getByRole("button", { name: "Verify" }).click();
  await page.waitForURL(`${BASE}/overview`);
  await page.getByRole("heading", { name: "Acme Robotics" }).waitFor();

  log("wrong password is refused without saying whether the account exists");
  const p2 = await browser.newPage();
  await p2.goto(`${BASE}/login`);
  await p2.getByLabel("Email").fill(owner.email);
  await p2.getByLabel("Password").fill("not the password");
  await p2.getByRole("button", { name: "Sign in" }).click();
  await expectText(p2, "Wrong email or password");
  await p2.close();

  log("forgot password: the reset link sets a new one and signs everyone out");
  const r = await browser.newContext();
  const rp = await r.newPage();
  watch(rp, "reset");
  await rp.goto(`${BASE}/forgot`);
  await rp.getByLabel("Email").fill(member.email);
  const askedAt = Date.now() - 2000;
  await rp.getByRole("button", { name: "Send reset link" }).click();
  await expectText(rp, "Check your email");
  await rp.goto(await mailLink(member.email, "/reset", { after: askedAt }));
  await rp.getByLabel("New password").fill("a brand new password");
  await rp.getByRole("button", { name: "Set password" }).click();
  await rp.waitForURL(/\/login\?reset=1/);
  await rp.getByLabel("Email").fill(member.email);
  await rp.getByLabel("Password").fill("a brand new password");
  await rp.getByRole("button", { name: "Sign in" }).click();
  await rp.waitForURL(`${BASE}/overview`);
  log("the member's other browser was signed out by the reset");
  await mpage.reload();
  await mpage.waitForURL(/\/login/, { timeout: 15000 });

  // ── Superadmin ──────────────────────────────────────────────────────────
  log("superadmin signs up (SUPERADMIN_EMAILS), sees every organisation");
  const actx = await browser.newContext({ viewport: { width: 1360, height: 900 } });
  const apage = await actx.newPage();
  watch(apage, "admin");
  await signUp(apage, admin);
  await apage.goto(`${BASE}/admin`);
  await apage.getByPlaceholder("Search name, email or id…").fill(owner.email);
  await expectText(apage, "Acme Robotics");
  await shot(apage, "admin");
  log("read-only impersonation: banner shows, writes are refused");
  apage.once("dialog", (d) => d.accept("Customer asked about an alert"));
  await apage.getByPlaceholder("Search name, email or id…").fill(owner.email);
  await apage.getByRole("row", { name: new RegExp(owner.email) }).waitFor();
  await apage.getByRole("row", { name: new RegExp(owner.email) }).getByRole("button", { name: "View" }).click();
  await apage.waitForURL(`${BASE}/overview`);
  await expectText(apage, "Superadmin view of");
  await expectText(apage, "read-only");
  await shot(apage, "impersonating");
  await apage.goto(`${BASE}/rules`);
  await expectText(apage, "Load above 40");
  await apage.getByRole("button", { name: "Leave" }).click();
  await apage.waitForURL(/\/admin/);
  await apage.getByRole("button", { name: "Impersonations" }).click();
  await expectText(apage, "Customer asked about an alert");
  await expectText(apage, "ended");

  log("the owner's audit log shows the superadmin's visit is not a change, and the owner's changes");
  await page.goto(`${BASE}/settings/audit`);
  await expectText(page, "Load above 40");

  log("the member deletes their account; they can't sign in again");
  await rp.goto(`${BASE}/settings`);
  rp.once("dialog", (d) => d.accept());
  await rp.getByLabel("Password", { exact: true }).last().fill("a brand new password");
  await rp.getByRole("button", { name: "Delete account" }).click();
  await rp.waitForURL(/\/login/);
  await rp.getByLabel("Email").fill(member.email);
  await rp.getByLabel("Password").fill("a brand new password");
  await rp.getByRole("button", { name: "Sign in" }).click();
  await expectText(rp, "Wrong email or password");

  log("mobile width: the menu opens and navigates");
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto(`${BASE}/servers`);
  await page.getByRole("button", { name: "Menu" }).click();
  await page.getByRole("link", { name: "Incidents" }).last().click();
  await page.waitForURL(/\/incidents/);
  await shot(page, "mobile");

  log("dark theme renders");
  await page.setViewportSize({ width: 1360, height: 900 });
  await page.emulateMedia({ colorScheme: "dark" });
  await page.evaluate(() => localStorage.removeItem("pg.theme"));
  await page.goto(`${BASE}/overview`);
  await shot(page, "dark-overview");
} finally {
  agent?.kill("SIGTERM");
  await browser.close();
}

if (errors.length) {
  console.error("\nErrors seen in the browser:\n" + errors.join("\n"));
  process.exit(1);
}
console.log("\nJourney passed.");
