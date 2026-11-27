// Browser smoke test for boosted navigation (#345) and static/keyboard.js.
//
// Run through the Rust harness, which serves the web router on a fixture and
// passes its address and a session cookie:
//
//   cargo test --lib browser_smoke -- --ignored --nocapture
//
// Needs Node and Playwright with Chromium (`npm i playwright` and
// `npx playwright install chromium`, or a machine that already has them).
// Exits non-zero, naming the first failed check, when anything is off.
//
//   node scripts/browser-smoke.mjs <base-url> <fr_session cookie value>

import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const { chromium } = require("playwright");

const [base, cookie] = process.argv.slice(2);
if (!base || !cookie) {
  console.error("usage: browser-smoke.mjs <base-url> <session-cookie>");
  process.exit(2);
}

const failures = [];
function check(name, ok, detail) {
  console.log(`${ok ? "ok  " : "FAIL"} ${name}${ok ? "" : `: ${JSON.stringify(detail)}`}`);
  if (!ok) failures.push(name);
}

const browser = await chromium.launch();
try {
  const newPage = async (viewport) => {
    const ctx = await browser.newContext({ viewport });
    await ctx.addCookies([{ name: "fr_session", value: cookie, url: base }]);
    const page = await ctx.newPage();
    const errors = [];
    page.on("pageerror", (e) => errors.push(e.message));
    return { page, errors };
  };
  const settle = (page) => page.waitForTimeout(400);
  const marker = (page) => page.evaluate(() => window.__frMarker === 1);
  const railTop = (page) => page.$eval(".rail-scroll", (e) => e.scrollTop);

  // ---- desktop, short viewport so the rail scrolls --------------------
  const { page, errors } = await newPage({ width: 1100, height: 260 });
  await page.goto(`${base}/`);
  await page.evaluate(() => { window.__frMarker = 1; });

  // A rail link swaps the page in: no reload, rail kept, focus on the heading.
  await page.$eval(".rail-scroll", (e) => { e.scrollTop = e.scrollHeight; });
  const link = page.locator('.rail-scroll .feed-link[href*="fun.example"]');
  await link.scrollIntoViewIfNeeded();
  const before = await railTop(page);
  await link.click();
  await page.waitForURL(/fun\.example/);
  await settle(page);
  check("rail link does not reload the page", await marker(page));
  check("rail keeps its scroll position", (await railTop(page)) === before, {
    before, after: await railTop(page),
  });
  const focused = await page.evaluate(() => {
    const a = document.activeElement;
    return a && a.matches("#content h1") ? a.textContent.trim() : a && a.outerHTML.slice(0, 80);
  });
  check("focus moves to the new page's heading", focused === "fun.example", focused);
  check(
    "the current feed is marked in the rail",
    (await page.locator('.feed-link[aria-current="page"][href*="fun.example"]').count()) === 1,
  );

  // Mark all read: a boosted POST that redirects lands on the same list.
  await page.click("#mark-all-form button");
  await settle(page);
  check("mark all read does not reload", await marker(page));
  check("mark all read returns to the same feed", /feed=https%3A%2F%2Ffun\.example/.test(page.url()), page.url());
  check("the list is now empty", (await page.locator(".empty-title").count()) === 1);

  // A boosted POST answered with an error page keeps the address it came
  // from, so a reload never GETs a POST-only URL.
  const urlBefore = page.url();
  await page.evaluate(() => {
    const f = document.createElement("form");
    f.method = "post";
    f.action = "/entries/999999/read";
    f.id = "fr-smoke-post";
    f.innerHTML = '<button type="submit">x</button>';
    document.querySelector("#content").appendChild(f);
    window.htmx.process(f);
  });
  await page.click("#fr-smoke-post button");
  await settle(page);
  check("an error answer to a POST is shown", /entry not found/.test(await page.textContent("body")));
  check("an error answer to a POST keeps the URL", page.url() === urlBefore, { urlBefore, now: page.url() });
  await page.goto(`${base}/`);
  await page.evaluate(() => { window.__frMarker = 1; });

  // While a page loads, the page says so.
  await page.route("**/?view=all", async (route) => {
    await new Promise((r) => setTimeout(r, 700));
    await route.continue();
  });
  const allTab = page.locator('.filter-opt[href="/?view=all"]');
  await allTab.click();
  await page.waitForTimeout(300);
  check("loading state shows during a slow navigation",
    await page.evaluate(() => document.documentElement.classList.contains("is-navigating")));
  await page.waitForURL(/view=all/);
  await settle(page);
  check("loading state clears after the swap",
    !(await page.evaluate(() => document.documentElement.classList.contains("is-navigating"))));
  await page.unroute("**/?view=all");

  // An entry, then the reader's own htmx control and shortcuts.
  await page.click(".entry .entry-main");
  await page.waitForURL(/\/entries\//);
  await settle(page);
  check("opening an entry does not reload", await marker(page));
  const pressed = await page.getAttribute(".actionbar-read", "aria-pressed");
  await page.keyboard.press("m");
  await settle(page);
  check("m toggles read on a swapped-in entry",
    (await page.getAttribute(".actionbar-read", "aria-pressed")) !== pressed);
  await page.keyboard.press("?");
  check("? opens the shortcuts overlay after swaps",
    await page.$eval("#kbd-overlay", (e) => e.classList.contains("is-open")));
  await page.keyboard.press("Escape");

  // Back reloads from the server (no snapshots are kept).
  await page.goBack();
  await page.waitForLoadState("load");
  await settle(page);
  check("back reloads the page", !(await marker(page)));
  check("htmx keeps no page snapshots",
    await page.evaluate(() => localStorage.getItem("htmx-history-cache") === null));

  // A form whose request gets no answer says so; nothing pretends it worked.
  await page.route("**/read-all*", (route) => route.abort("internetdisconnected"));
  const markAll = page.locator("#mark-all-form button");
  if (await markAll.count()) {
    await markAll.click();
    await settle(page);
    check("an unanswered form shows an alert",
      (await page.locator('#fr-offline[role="alert"]').count()) === 1);
  } else {
    check("an unanswered form shows an alert (needs an unread list)", false, "no mark-all button");
  }
  await page.unroute("**/read-all*");

  check("no page errors (desktop)", errors.length === 0, errors);

  // ---- phone: the drawer works before and after a swap ------------------
  const m = await newPage({ width: 390, height: 700 });
  const open = () => m.page.$eval("#shell", (e) => e.classList.contains("rail-open"));
  await m.page.goto(`${base}/?view=all`);
  await m.page.click("#rail-toggle");
  check("drawer opens", await open());
  await m.page.click('.feed-link[href*="work.example"]');
  await settle(m.page);
  check("drawer is closed after navigating", !(await open()));
  await m.page.click("#rail-toggle");
  check("drawer opens again after a swap", await open());
  await m.page.click("#rail-close");
  check("drawer closes after a swap", !(await open()));
  check("no page errors (phone)", m.errors.length === 0, m.errors);
} finally {
  await browser.close();
}

if (failures.length) {
  console.error(`${failures.length} check(s) failed`);
  process.exit(1);
}
console.log("all checks passed");
