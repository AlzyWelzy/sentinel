// Fleet wall, saved views and incident merge, in the browser.
import { execFileSync } from "node:child_process";
import { chromium } from "playwright";

const BASE = process.env.BASE ?? "http://localhost:3000";
const email = `extras-${Date.now().toString(36)}@example.com`;
const psql = (sql) => execFileSync("docker", ["exec", "beyond-dev-postgres-1", "psql", "-U", "sentinel", "-d", "sentinel", "-qAtc", sql]).toString().trim();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const errors = [];

const b = await chromium.launch();
const p = await b.newPage({ viewport: { width: 1360, height: 900 } });
p.on("pageerror", (e) => errors.push(e.message));
await p.goto(`${BASE}/signup`);
await p.getByLabel("Name", { exact: true }).fill("Extra");
await p.getByLabel("Work email").fill(email);
await p.getByLabel("Password").fill("extras password 123");
const after = Date.now() - 2000;
await p.getByRole("button", { name: "Create account" }).click();
await p.getByText("Check your email").waitFor();
let link;
for (let i = 0; i < 30 && !link; i++) {
  const r = await fetch(`http://localhost:8035/api/v1/search?query=to:${email}`).then((r) => r.json());
  for (const m of r.messages) if (Date.parse(m.Created) >= after) {
    const t = await fetch(`http://localhost:8035/api/v1/message/${m.ID}`).then((r) => r.json());
    const x = t.Text.match(/token=([A-Za-z0-9_%-]+)/); if (x) link = `${BASE}/verify?token=${x[1]}`;
  }
  await sleep(1000);
}
await p.goto(link);
await p.waitForURL(/welcome/);
await p.goto(`${BASE}/overview`);
await p.getByText("No servers yet").waitFor();
const tid = psql(`select m.tenant_id from tenant_members m join users u on u.id=m.user_id where u.email='${email}'`);
const host = psql(`insert into hosts (tenant_id, machine_id, hostname, token_hash, tags) values ('${tid}', md5(random()::text), 'web-extra', md5(random()::text), '{web}') returning id`);
for (const n of [1, 2]) psql(`insert into incidents (id, tenant_id, host_id, status, summary, rule_name, hostname, opened_at, severity) values (gen_random_uuid(), '${tid}', '${host}', 'open', 'Disk full ${n}', 'Disk', 'web-extra', now() - interval '${n} minutes', 'critical')`);

console.log("1. fleet wall shows the server");
await p.goto(`${BASE}/fleet`);
await p.getByText("web-extra").waitFor();
await p.screenshot({ path: "shots/extras-wall.png" });

console.log("2. saved view: save the servers filter, clear it, apply it again");
await p.goto(`${BASE}/servers?tag=web`);
p.once("dialog", (d) => d.accept("Web servers"));
await p.getByRole("button", { name: "Save view" }).click();
await p.getByLabel("Saved views").waitFor();
await p.goto(`${BASE}/servers`);
await p.getByLabel("Saved views").selectOption({ label: "Web servers" });
await p.waitForURL(/tag=web/);
await p.getByRole("button", { name: "Delete this view" }).click();
await p.getByLabel("Saved views").waitFor({ state: "detached" });

console.log("3. merge two open incidents into the first");
await p.goto(`${BASE}/incidents`);
await p.getByLabel("Select Disk full 1").check();
await p.getByLabel("Select Disk full 2").check();
await p.getByRole("button", { name: /Merge 2 into the first/ }).click();
for (let i = 0; i < 20; i++) {
  if (psql(`select count(*) from incidents where tenant_id='${tid}' and merged_into is not null`) === "1") break;
  await sleep(500);
}
const merged = psql(`select count(*) from incidents where tenant_id='${tid}' and merged_into is not null`);
if (merged !== "1") throw new Error(`merged ${merged}`);
await p.screenshot({ path: "shots/extras-merged.png" });
await b.close();
if (errors.length) { console.error(errors.join("\n")); process.exit(1); }
console.log("Extras passed.");
