// Chrome DevTools Recorder → browser check steps.
//
// In Chrome: DevTools → Recorder → record the flow → Export → JSON. Paste it
// here and each recorded step becomes a check step (agent/checks/browser.go):
// navigate → goto, click → click, change → type, waitForElement → wait.
// Typed passwords become {{password}} (and the first typed email or user
// name {{username}}) so secrets live in the masked fields, not in the steps.

export type Step = {
  action: "goto" | "click" | "type" | "wait" | "expect_text" | "expect_no_text" | "sleep";
  selector?: string;
  text?: string;
  url?: string;
  ms?: number;
};

type Recorded = {
  type: string;
  url?: string;
  value?: string;
  selectors?: (string | string[])[];
  visible?: boolean;
};

const MAX_STEPS = 25;
const NOT_CSS = /^(aria|xpath|pierce|text)\//;

/** The first selector Chrome recorded that's plain CSS (it also records
 * ARIA, XPath and text forms, which the agent doesn't take). */
export function cssSelector(selectors: Recorded["selectors"]): string | null {
  for (const s of selectors ?? []) {
    const parts = Array.isArray(s) ? s : [s];
    // A list is a path through shadow roots or frames: only a single one works here.
    const only = parts.length === 1 ? parts[0] : undefined;
    if (only && !NOT_CSS.test(only)) return only;
  }
  return null;
}

export type Converted = {
  steps: Step[];
  skipped: string[];
  target: string | null;
  secrets: Record<string, string>;
};

export function fromRecorder(json: string): Converted {
  let doc: { steps?: Recorded[] };
  try {
    doc = JSON.parse(json);
  } catch {
    throw new Error("That isn't JSON. In Chrome's Recorder, use Export → JSON.");
  }
  if (!doc || !Array.isArray(doc.steps)) {
    throw new Error("No steps found. Export the recording from Chrome's Recorder as JSON.");
  }
  const steps: Step[] = [];
  const skipped: string[] = [];
  const secrets: Record<string, string> = {};
  let target: string | null = null;
  for (const r of doc.steps) {
    switch (r.type) {
      case "navigate":
        if (!r.url) break;
        if (target === null) target = r.url;
        else steps.push({ action: "goto", url: r.url });
        break;
      case "click":
      case "doubleClick": {
        const sel = cssSelector(r.selectors);
        if (sel) steps.push({ action: "click", selector: sel });
        else skipped.push(`${r.type} (no CSS selector recorded)`);
        break;
      }
      case "change": {
        const sel = cssSelector(r.selectors);
        if (!sel) {
          skipped.push("typing (no CSS selector recorded)");
          break;
        }
        let text = r.value ?? "";
        if (/pass(word)?|pwd/i.test(sel)) {
          secrets.password = text;
          text = "{{password}}";
        } else if (!secrets.username && /user|email|login/i.test(sel)) {
          secrets.username = text;
          text = "{{username}}";
        }
        steps.push({ action: "type", selector: sel, text });
        break;
      }
      case "waitForElement": {
        const sel = cssSelector(r.selectors);
        if (sel && r.visible !== false) steps.push({ action: "wait", selector: sel });
        else skipped.push("wait for an element (not a CSS selector, or waiting for it to go)");
        break;
      }
      case "setViewport":
      case "keyDown":
      case "keyUp":
      case "scroll":
      case "hover":
        break; // the check's own browser handles these
      default:
        skipped.push(r.type);
    }
  }
  if (steps.length > MAX_STEPS) {
    skipped.push(`${steps.length - MAX_STEPS} steps past the limit of ${MAX_STEPS}`);
    steps.length = MAX_STEPS;
  }
  return { steps, skipped, target, secrets };
}
