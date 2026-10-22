// Shared harness for the console browser journeys (Journey B onward). The
// helpers and the accessibility audit are the same as in
// console_journey_a.mjs, which keeps its own copy unchanged.
import { createRequire } from 'node:module';
import fs from 'node:fs';
import path from 'node:path';

const require = createRequire(import.meta.url);
const { chromium } = require(process.env.SERK_PLAYWRIGHT);
export const BASE = process.env.SERK_URL + '/console/';
export const FX = JSON.parse(fs.readFileSync(process.env.SERK_FIXTURE, 'utf8'));
const SHOTS = process.env.SERK_SHOTS;
export const T = FX.tokens;
export const failures = [];
export const log = (...a) => console.log(new Date().toISOString().slice(11, 23), ...a);
export const fail = (msg) => { failures.push(msg); console.log('FAIL:', msg); };
let shot = 0;

export const browser = await chromium.launch();
export const pages = {};

export async function as(role, opts = {}) {
  if (pages[role]) return pages[role];
  const ctx = await browser.newContext({ viewport: opts.viewport || { width: 1280, height: 900 }, colorScheme: opts.colorScheme || 'light' });
  const p = await ctx.newPage();
  p.on('pageerror', (e) => fail(`[${role}] uncaught script error: ${e.message}`));
  p.on('console', (m) => {
    if (m.type() === 'error' && /Content Security Policy|Refused to/.test(m.text())) fail(`[${role}] CSP violation: ${m.text()}`);
  });
  await p.goto(BASE);
  await p.getByLabel('Access token').fill(T[role]);
  await p.getByRole('button', { name: 'Sign in' }).click();
  await p.getByRole('heading', { level: 1, name: 'My work' }).waitFor();
  pages[role] = p;
  return p;
}

export async function nav(p, hash, heading) {
  await p.evaluate((h) => {
    if (location.hash === h) window.dispatchEvent(new HashChangeEvent('hashchange'));
    else location.hash = h;
  }, hash);
  if (heading) await p.getByRole('heading', { level: 1, name: heading }).waitFor();
}
export const h1 = async (p) => (await p.getByRole('heading', { level: 1 }).textContent()).trim();
export const idFromHash = async (p) => (await p.evaluate(() => location.hash)).split('/').pop();

export async function act(p, button, expect) {
  await p.getByRole('button', { name: button, exact: true }).click();
  const n = p.locator('p.notice').filter({ hasText: expect });
  await n.first().waitFor({ timeout: 15000 }).catch(async () => {
    const alert = (await p.locator('#alert').isVisible()) ? await p.locator('#alert').textContent() : '(no alert)';
    throw new Error(`"${button}" did not report "${expect}"; alert: ${alert}`);
  });
}

export async function selectByText(locator, text) {
  const opts = await locator.locator('option').allTextContents();
  const label = opts.find((o) => o.includes(text));
  if (!label) throw new Error(`no option containing "${text}" in [${opts.join(' | ')}]`);
  await locator.selectOption({ label });
}

export async function snap(p, name) {
  if (!SHOTS) return;
  shot += 1;
  await p.screenshot({ path: path.join(SHOTS, `${String(shot).padStart(2, '0')}-${name}.png`), fullPage: true });
}

// In-page accessibility audit (structural checks + WCAG 2.2 AA contrast).
export async function audit(p, where) {
  // Measure the settled state, not a frame in the middle of a transition.
  await p.evaluate(() => document.getAnimations().forEach((a) => a.finish()));
  const problems = await p.evaluate(() => {
    const out = [];
    const visible = (el) => !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length) && getComputedStyle(el).visibility !== 'hidden';
    for (const el of document.querySelectorAll('input:not([type=hidden]), select, textarea')) {
      if (!visible(el)) continue;
      const lbl = (el.labels && [...el.labels].map((l) => l.textContent.trim()).join(' ')) || el.getAttribute('aria-label') || '';
      if (!lbl.trim()) out.push(`unlabelled <${el.tagName.toLowerCase()} name=${el.name}>`);
    }
    for (const b of document.querySelectorAll('button, a[href]')) {
      if (!visible(b)) continue;
      if (!(b.getAttribute('aria-label') || b.textContent || '').trim()) out.push(`nameless <${b.tagName.toLowerCase()}>`);
    }
    if (document.querySelectorAll('h1').length !== 1) out.push(`h1 count ${document.querySelectorAll('h1').length}`);
    if (!document.querySelector('main')) out.push('no <main> landmark');
    const ids = [...document.querySelectorAll('[id]')].map((e) => e.id);
    const dup = [...new Set(ids.filter((x, i) => ids.indexOf(x) !== i))];
    if (dup.length) out.push(`duplicate ids: ${dup.join(',')}`);
    // Contrast.
    const parse = (c) => { const m = c.match(/rgba?\(([^)]+)\)/); if (!m) return null; const v = m[1].split(/[ ,/]+/).filter(Boolean).map(Number); return { r: v[0], g: v[1], b: v[2], a: v.length > 3 ? v[3] : 1 }; };
    const lin = (x) => { x /= 255; return x <= 0.03928 ? x / 12.92 : ((x + 0.055) / 1.055) ** 2.4; };
    const L = (c) => 0.2126 * lin(c.r) + 0.7152 * lin(c.g) + 0.0722 * lin(c.b);
    const bgOf = (el) => {
      for (let e = el; e; e = e.parentElement) {
        const c = parse(getComputedStyle(e).backgroundColor);
        if (c && c.a > 0.5) return c;
      }
      return parse(getComputedStyle(document.body).backgroundColor) || { r: 255, g: 255, b: 255, a: 1 };
    };
    const seen = new Set();
    for (const el of document.querySelectorAll('body *')) {
      if (!visible(el) || el.closest('.sr, [hidden]') || el.closest('[disabled]')) continue;
      if (![...el.childNodes].some((n) => n.nodeType === 3 && n.textContent.trim())) continue;
      let op = 1;
      for (let e = el; e; e = e.parentElement) op *= Number(getComputedStyle(e).opacity);
      if (op < 1) continue;
      const cs = getComputedStyle(el);
      const fg = parse(cs.color);
      const bg = bgOf(el);
      if (!fg || !bg) continue;
      const l1 = L(fg), l2 = L(bg);
      const ratio = (Math.max(l1, l2) + 0.05) / (Math.min(l1, l2) + 0.05);
      const size = parseFloat(cs.fontSize), bold = Number(cs.fontWeight) >= 700;
      const need = size >= 24 || (size >= 18.66 && bold) ? 3 : 4.5;
      if (ratio < need) {
        const key = `${el.tagName}.${el.className}:${cs.color}/${cs.backgroundColor}`;
        if (!seen.has(key)) { seen.add(key); out.push(`contrast ${ratio.toFixed(2)} < ${need} on <${el.tagName.toLowerCase()} class="${el.className}"> "${el.textContent.trim().slice(0, 30)}"`); }
      }
    }
    // Rendering bugs that leak programming values into the page.
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    for (let n = walker.nextNode(); n; n = walker.nextNode()) {
      const v = n.textContent.trim();
      if (/^(null|undefined|NaN|\[object Object\])+$/.test(v) && n.parentElement && visible(n.parentElement)) out.push(`stray text "${v}" in <${n.parentElement.tagName.toLowerCase()}>`);
    }
    if (document.documentElement.scrollWidth > window.innerWidth + 1) out.push(`horizontal scroll: ${document.documentElement.scrollWidth} > ${window.innerWidth}`);
    return out;
  });
  if (problems.length) fail(`accessibility (${where}): ${problems.join('; ')}`);
  else log(`a11y ok: ${where}`);
}

