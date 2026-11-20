// The Network pages in a browser: every page renders with real (simulated)
// devices and no console errors. Run api/network_setup.py first and pass
// its EMAIL and PASSWORD (and SCAN_IP, this machine's address, for the
// discovery step).
import { mkdirSync } from "node:fs";

import { chromium } from "playwright";

const BASE = process.env.BASE ?? "http://localhost:3000";
const { EMAIL, PASSWORD } = process.env;
mkdirSync("shots", { recursive: true });
const errors = [];
const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1360, height: 900 } });
// Before signing in, the page's session check answers 401: expected.
let signedIn = false;
page.on("console", (m) => m.type() === "error" && signedIn && errors.push(m.text()));
page.on("pageerror", (e) => errors.push(e.message));
page.on("response", (r) => r.status() >= 400 && console.log(`  ${r.status()} ${r.request().method()} ${r.url()}`));
const step = (s) => console.log(s);

await page.goto(`${BASE}/login`);
await page.getByLabel("Email").fill(EMAIL);
await page.getByLabel("Password").fill(PASSWORD);
await page.getByRole("button", { name: "Sign in" }).click();
await page.waitForURL(/\/(overview|welcome)/);
signedIn = true;

step("1. devices list shows both devices, named from sysName");
await page.goto(`${BASE}/network`);
await page.getByText("host-754862").waitFor({ timeout: 120000 });
await page.getByText("host-c6cb35").waitFor({ timeout: 60000 });
await page.screenshot({ path: "shots/network-list.png", fullPage: true });

step("2. device page: interfaces, neighbours, system, traffic");
await page.getByText("host-754862").click();
await page.getByText("Interfaces up").waitFor();
await page.getByText("Neighbours (LLDP)").waitFor();
await page.getByRole("cell", { name: /^Ethernet/ }).first().waitFor();
await page.screenshot({ path: "shots/network-device.png", fullPage: true });

step("3. tag a port for billing");
await page.getByRole("button", { name: "+ tag" }).first().click();
await page.getByLabel("Billing tag").fill("Acme Ltd");
await page.getByRole("button", { name: "Save", exact: true }).first().click();
await page.getByText("Acme Ltd").first().waitFor();

step("4. topology");
await page.goto(`${BASE}/network/topology`);
await page.getByRole("img", { name: "Network topology" }).waitFor();
await page.screenshot({ path: "shots/network-topology.png", fullPage: true });

step("5. bandwidth for the tag");
await page.goto(`${BASE}/network/bandwidth`);
await page.getByText("Billable (95th)").waitFor();
await page.screenshot({ path: "shots/network-bandwidth.png", fullPage: true });

step("6. credentials: secrets aren't shown; add a v3 user");
await page.goto(`${BASE}/network/credentials`);
await page.getByRole("cell", { name: "arista-eos" }).waitFor();
if ((await page.content()).includes("community=")) throw new Error("community shown");
await page.getByRole("button", { name: "Add credential" }).click();
const v3 = `v3 monitor ${Date.now().toString(36)}`;
await page.getByLabel("Name", { exact: true }).fill(v3);
await page.getByLabel("SNMP version").selectOption("3");
await page.getByLabel("Username").fill("monitor");
await page.getByLabel("Authentication password").fill("auth-pass-1");
await page.getByLabel("Encryption password").fill("priv-pass-1");
await page.getByRole("button", { name: "Add credential" }).last().click();
await page.getByRole("cell", { name: v3 }).waitFor();
await page.screenshot({ path: "shots/network-credentials.png", fullPage: true });

step("7. a network rule from the rule form");
await page.goto(`${BASE}/rules`);
await page.getByText("Interface down").first().waitFor();
await page.getByRole("button", { name: "New rule" }).click();
const rule = `Uplinks busy ${Date.now().toString(36)}`;
await page.getByLabel("Name", { exact: true }).fill(rule);
await page.getByLabel("Kind").selectOption("network");
await page.getByLabel("Condition").selectOption("interface_utilisation");
await page.getByLabel("Threshold").fill("80");
await page.getByRole("button", { name: "Create rule" }).click();
await page.getByText(rule).waitFor();

step("8. discovery: a scan is listed and can be cancelled");
// This machine's own address on port 161 (the simulator answers on 1161),
// so nothing else on the network is probed.
if (process.env.SCAN_IP) {
  await page.goto(`${BASE}/network`);
  await page.getByRole("button", { name: "Discover" }).click();
  await page.getByLabel("Range").fill(`${process.env.SCAN_IP}/32`);
  await page.getByRole("button", { name: "Scan", exact: true }).click();
  await page.getByText(`${process.env.SCAN_IP}/32 ·`).waitFor();
  await page.getByRole("button", { name: "Cancel" }).click();
  await page.getByText(/Cancelled\./).waitFor();
  await page.screenshot({ path: "shots/network-discovery.png", fullPage: true });
} else {
  console.log("  skipped: set SCAN_IP");
}

step("9. servers list doesn't list devices; phone width");
await page.goto(`${BASE}/servers`);
await page.getByText("1 in this organisation").waitFor();
await page.setViewportSize({ width: 360, height: 800 });
await page.goto(`${BASE}/network`);
await page.getByText("host-754862").waitFor();
const wide = await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth + 1);
if (wide) throw new Error("the network page scrolls sideways at 360px");
await page.screenshot({ path: "shots/network-mobile.png", fullPage: true });

await browser.close();
const real = errors.filter((e) => !/favicon|DevTools/.test(e));
if (real.length) {
  console.log("Errors seen in the browser:\n" + real.join("\n"));
  process.exit(1);
}
console.log("Network UI passed.");
