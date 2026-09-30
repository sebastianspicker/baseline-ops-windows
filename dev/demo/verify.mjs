// Exercises the browser tour and optionally captures the README's demo screenshots.
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { readFile, mkdir, mkdtemp, copyFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";

const root = new URL("../../docs/demo/", import.meta.url);
const assets = new Map([
  ["/", ["index.html", "text/html"]],
  ["/index.html", ["index.html", "text/html"]],
  ["/styles.css", ["styles.css", "text/css"]],
  ["/app.js", ["app.js", "text/javascript"]],
  ["/profiles.json", ["profiles.json", "application/json"]],
]);
const server = createServer(async (request, response) => {
  const asset = assets.get(new URL(request.url, "http://localhost").pathname);
  if (!asset) {
    response.writeHead(404).end();
    return;
  }
  try {
    response.writeHead(200, { "Content-Type": asset[1] });
    response.end(await readFile(new URL(asset[0], root)));
  } catch {
    response.writeHead(500).end();
  }
});
await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
const origin = `http://127.0.0.1:${server.address().port}`;
let browser;
const capture = process.argv.includes("--screenshots");
const screenshotDir = new URL("../../docs/screenshots/", import.meta.url);
const staging = await mkdtemp(join(tmpdir(), "baselineops-tour-"));
const captured = [];

async function assertNoOverflow(page) {
  assert.equal(
    await page.evaluate(
      () => document.documentElement.scrollWidth > innerWidth,
    ),
    false,
    "Horizontal page overflow",
  );
}
async function selectStep(page, step) {
  await page.locator(`[data-step="${step}"]`).click();
  assert.equal(await page.locator(`#${step}`).isVisible(), true);
}
async function captureStep(page, name) {
  if (!capture) return;
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.screenshot({ path: join(staging, name), fullPage: true });
  captured.push(name);
}

try {
  browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({
    viewport: { width: 1440, height: 1100 },
    deviceScaleFactor: 1,
  });
  await context.grantPermissions(["clipboard-read", "clipboard-write"], {
    origin,
  });
  const page = await context.newPage();
  const errors = [];
  page.on("pageerror", (error) => errors.push(error.message));
  page.on("console", (message) => {
    if (message.type() === "error") errors.push(message.text());
  });
  await page.goto(origin);
  await page.waitForFunction(
    () => !document.getElementById("profile").disabled,
  );
  assert.equal(await page.locator("#script-list li").count(), 3);
  await assertNoOverflow(page);
  if (capture) await mkdir(screenshotDir, { recursive: true });
  await captureStep(page, "01-profiles.png");

  for (const name of [
    "endpoint-health-check",
    "rapid-triage",
    "baseline-audit",
  ]) {
    await page.selectOption("#profile", name);
    const displayed = JSON.parse(
      await page.locator("#profile-json").textContent(),
    );
    const original = JSON.parse(
      await readFile(
        new URL(`../../examples/profiles/${name}.json`, import.meta.url),
        "utf8",
      ),
    );
    assert.deepEqual(displayed, original);
    assert.equal(
      await page.locator("#script-list li").count(),
      original.Steps.length,
    );
  }
  await page.locator("#next-step").click();
  assert.equal(await page.locator("#command").isVisible(), true);
  assert.match(
    await page.locator("#command-text").textContent(),
    /-Mode Audit -OutputFormat Json/,
  );
  await page.check("#whatif");
  assert.match(await page.locator("#command-text").textContent(), / -WhatIf$/);
  await captureStep(page, "02-command.png");
  for (const value of ["Console", "Csv", "None", "Json"]) {
    await page.selectOption("#output", value);
    assert.ok(
      (await page.locator("#command-text").textContent()).includes(
        `-OutputFormat ${value}`,
      ),
    );
  }
  await page.locator("#copy-command").click();
  await page.waitForFunction(() =>
    document
      .getElementById("announcement")
      .textContent.startsWith("Command copied"),
  );
  assert.equal(
    await page.evaluate(() => navigator.clipboard.readText()),
    await page.locator("#command-text").textContent(),
  );
  await page.evaluate(() => {
    navigator.clipboard.writeText = async () => {
      throw new Error("Denied by test");
    };
  });
  await page.locator("#copy-command").click();
  await page.waitForFunction(() =>
    document
      .getElementById("announcement")
      .textContent.startsWith("Clipboard access is unavailable"),
  );
  await page.uncheck("#whatif");
  assert.equal(
    (await page.locator("#command-text").textContent()).includes("-WhatIf"),
    false,
  );

  await selectStep(page, "result");
  assert.equal(await page.locator("#findings article").count(), 2);
  await captureStep(page, "03-result.png");
  await page.selectOption("#severity", "Medium");
  assert.equal(await page.locator("#findings article").count(), 1);
  await page.selectOption("#severity", "High");
  assert.match(
    await page.locator("#findings").textContent(),
    /No sample findings/,
  );
  await page.selectOption("#severity", "all");
  const downloadEvent = page.waitForEvent("download");
  await page.locator("#download-result").click();
  const download = await downloadEvent;
  assert.equal(download.suggestedFilename(), "baselineops-sample-result.json");
  const downloaded = JSON.parse(await readFile(await download.path(), "utf8"));
  assert.equal(downloaded.Metadata.Demo, true);
  assert.deepEqual(
    downloaded,
    JSON.parse(await page.locator("#result-json").textContent()),
  );
  await page.locator("#result summary").click();
  assert.equal(await page.locator("#result-json").isVisible(), true);
  await page.locator("#next-step").click();
  assert.equal(
    await page
      .locator("#profiles-title")
      .evaluate((element) => element === document.activeElement),
    true,
  );
  assert.deepEqual(errors, []);

  for (const width of [390, 320, 768]) {
    await page.setViewportSize({ width, height: 844 });
    for (const step of ["profiles", "command", "result"]) {
      await selectStep(page, step);
      await assertNoOverflow(page);
    }
  }
  await page.setViewportSize({ width: 390, height: 844 });
  await selectStep(page, "profiles");
  if (capture) {
    const previewDir = new URL("../../.ci-artifacts/", import.meta.url);
    await mkdir(previewDir, { recursive: true });
    await page.screenshot({
      path: fileURLToPath(new URL("mobile-preview.png", previewDir)),
      fullPage: true,
    });
  }
  await page.goto(origin);
  await page.keyboard.press("Tab");
  assert.equal(
    await page
      .locator(".skip")
      .evaluate((element) => element === document.activeElement),
    true,
  );
  await page.keyboard.press("Enter");
  assert.equal(new URL(page.url()).hash, "#workspace");

  const failed = await context.newPage();
  await failed.route("**/profiles.json", (route) =>
    route.fulfill({ status: 503, body: "" }),
  );
  await failed.goto(origin);
  await failed.locator("#load-error").waitFor({ state: "visible" });
  assert.equal(await failed.locator("#profile").isDisabled(), true);
  assert.equal(await failed.locator("#copy-command").isDisabled(), true);
  await selectStep(failed, "result");
  assert.equal(await failed.locator("#findings article").count(), 2);
  await failed.close();

  const noScript = await browser.newContext({ javaScriptEnabled: false });
  const fallback = await noScript.newPage();
  await fallback.goto(origin);
  assert.match(
    await fallback.locator("noscript").textContent(),
    /Enable JavaScript/,
  );
  await noScript.close();
  for (const name of captured)
    await copyFile(join(staging, name), new URL(name, screenshotDir));
  console.log(
    `PASS: profiles, command options, clipboard, sample download, filters, empty/error states, keyboard, and 320/390/768px layouts${capture ? "; screenshots captured" : ""}.`,
  );
} finally {
  await rm(staging, { recursive: true, force: true });
  await browser?.close();
  await new Promise((resolve, reject) =>
    server.close((error) => (error ? reject(error) : resolve())),
  );
}
