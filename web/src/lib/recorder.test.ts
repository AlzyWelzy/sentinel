// Run: npm test (node's own test runner; no framework needed).
import assert from "node:assert/strict";
import { test } from "node:test";

import { cssSelector, fromRecorder } from "./recorder.ts";

const recording = {
  title: "Log in",
  steps: [
    { type: "setViewport", width: 1280, height: 800 },
    { type: "navigate", url: "https://shop.example.com/login" },
    { type: "click", selectors: [["aria/Email"], ["#email"]] },
    { type: "change", value: "me@example.com", selectors: [["aria/Email"], ["#email"]] },
    { type: "change", value: "hunter2", selectors: [["input[name=password]"]] },
    { type: "keyDown", key: "Enter" },
    { type: "click", selectors: [["pierce/#shadow", "button"], ["xpath//button"]] },
    { type: "waitForElement", selectors: [[".dashboard"]] },
    { type: "customStep", name: "x" },
  ],
};

test("a Chrome Recorder export becomes check steps", () => {
  const out = fromRecorder(JSON.stringify(recording));
  assert.equal(out.target, "https://shop.example.com/login");
  assert.deepEqual(out.steps, [
    { action: "click", selector: "#email" },
    { action: "type", selector: "#email", text: "{{username}}" },
    { action: "type", selector: "input[name=password]", text: "{{password}}" },
    { action: "wait", selector: ".dashboard" },
  ]);
  assert.deepEqual(out.secrets, { username: "me@example.com", password: "hunter2" });
  assert.equal(out.skipped.length, 2);
});

test("only plain CSS selectors are used", () => {
  assert.equal(cssSelector([["aria/Go"], ["text/Go"], [".go"]]), ".go");
  assert.equal(cssSelector([["#host", "button"]]), null);
});

test("not a recording", () => {
  assert.throws(() => fromRecorder("nope"), /isn't JSON/);
  assert.throws(() => fromRecorder("{}"), /No steps/);
});
