// Browser end-to-end test of the SERK console: Journey A (procure-to-pay)
// driven through the real UI by fifteen different people, each in their own
// browser context with their own token, against a real server and a real
// PostgreSQL database. Started by internal/httpapi/console_browser_test.go,
// which seeds master data, provides the tokens and verifies the outcome
// independently through the API afterwards.
//
// Also checks, on the pages it visits: labels and accessible names, one h1,
// landmarks, unique ids, WCAG AA text contrast (light and dark), no
// horizontal scrolling at phone width, a keyboard skip link, no uncaught
// script errors and no Content-Security-Policy violations.
import { createRequire } from 'node:module';
import fs from 'node:fs';
import path from 'node:path';

const require = createRequire(import.meta.url);
const { chromium } = require(process.env.SERK_PLAYWRIGHT);
const BASE = process.env.SERK_URL + '/console/';
const FX = JSON.parse(fs.readFileSync(process.env.SERK_FIXTURE, 'utf8'));
const SHOTS = process.env.SERK_SHOTS;
const T = FX.tokens;
const failures = [];
const log = (...a) => console.log(new Date().toISOString().slice(11, 23), ...a);
const fail = (msg) => { failures.push(msg); console.log('FAIL:', msg); };
let shot = 0;

const browser = await chromium.launch();
const pages = {};

async function as(role, opts = {}) {
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

async function nav(p, hash, heading) {
  await p.evaluate((h) => {
    if (location.hash === h) window.dispatchEvent(new HashChangeEvent('hashchange'));
    else location.hash = h;
  }, hash);
  if (heading) await p.getByRole('heading', { level: 1, name: heading }).waitFor();
}
const h1 = async (p) => (await p.getByRole('heading', { level: 1 }).textContent()).trim();
const idFromHash = async (p) => (await p.evaluate(() => location.hash)).split('/').pop();

async function act(p, button, expect) {
  await p.getByRole('button', { name: button, exact: true }).click();
  const n = p.locator('p.notice').filter({ hasText: expect });
  await n.first().waitFor({ timeout: 15000 }).catch(async () => {
    const alert = (await p.locator('#alert').isVisible()) ? await p.locator('#alert').textContent() : '(no alert)';
    throw new Error(`"${button}" did not report "${expect}"; alert: ${alert}`);
  });
}

async function selectByText(locator, text) {
  const opts = await locator.locator('option').allTextContents();
  const label = opts.find((o) => o.includes(text));
  if (!label) throw new Error(`no option containing "${text}" in [${opts.join(' | ')}]`);
  await locator.selectOption({ label });
}

async function snap(p, name) {
  if (!SHOTS) return;
  shot += 1;
  await p.screenshot({ path: path.join(SHOTS, `${String(shot).padStart(2, '0')}-${name}.png`), fullPage: true });
}

// In-page accessibility audit (structural checks + WCAG 2.2 AA contrast).
async function audit(p, where) {
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

try {
  // ---- keyboard: the sign-in field has focus; the skip link precedes it ---------
  {
    const ctx = await browser.newContext();
    const p = await ctx.newPage();
    await p.goto(BASE);
    const first = await p.evaluate(() => document.activeElement && document.activeElement.getAttribute('name'));
    if (first !== 'token') fail(`sign-in page focus is on "${first}", not the token field`);
    // Walking back from the token field passes only labelled header controls
    // (the day/night switch) and reaches the visible skip link first in order.
    let skip = null;
    for (let i = 0; i < 4 && !skip; i++) {
      await p.keyboard.press('Shift+Tab');
      const el = await p.evaluate(() => { const a = document.activeElement; return { text: a.textContent.trim(), label: a.getAttribute('aria-label') || '', left: a.getBoundingClientRect().left }; });
      if (el.text === 'Skip to content') skip = el;
      else if (!el.text && !el.label) fail(`Shift+Tab reaches an unlabelled control at x=${el.left}`);
    }
    if (!skip || skip.left < 0) fail(`Shift+Tab from the token field does not reach a visible skip link`);
    await audit(p, 'sign-in page');
    await ctx.close();
  }

  // ---- 1. Requisition: site engineer creates and submits ------------------------
  const se = await as('siteEng');
  await audit(se, 'home (site engineer)');
  await nav(se, '#/new/requisition', 'New requisition');
  await se.getByLabel('Cost code, line 1').waitFor();
  await se.getByLabel('Justification').fill('Level 3 slab reinforcement and concrete');
  await se.getByLabel('Description, line 1').fill('Reinforcement steel Grade 60');
  await se.getByLabel('Unit, line 1').fill('t');
  await se.getByLabel('Quantity, line 1').fill('20');
  await se.getByLabel('Estimated unit price, line 1').fill('86000');
  await se.getByRole('button', { name: 'Add line' }).click();
  await se.getByLabel('Description, line 2').fill('OPC cement 50kg');
  await se.getByLabel('Unit, line 2').fill('bag');
  await se.getByLabel('Quantity, line 2').fill('500');
  await se.getByLabel('Estimated unit price, line 2').fill('960');
  await audit(se, 'requisition form');
  await se.getByRole('button', { name: 'Create requisition' }).click();
  await se.getByRole('heading', { level: 1, name: /^Requisition PR-/ }).waitFor();
  const prID = await idFromHash(se);
  await act(se, 'Submit for approval', 'Submit for approval: done');
  log('requisition', await h1(se), 'submitted');

  // ---- 2. Project manager approves (budget checked by the database) -------------
  const pm = await as('pm');
  await nav(pm, `#/doc/purchase_requisition/${prID}`, /^Requisition PR-/);
  await act(pm, 'Approve', 'Approve: done');
  await snap(pm, 'requisition-approved');

  // ---- 3. RFQ to three suppliers, three quotes ----------------------------------
  const buyer = await as('buyer');
  await nav(buyer, `#/doc/purchase_requisition/${prID}`, /^Requisition PR-/);
  await buyer.getByRole('link', { name: 'Create RFQ' }).click();
  await buyer.getByRole('heading', { level: 1, name: 'New RFQ' }).waitFor();
  for (const code of ['ABC-STEEL', 'HABESHA-CEMENT', 'SAFARI-BUILD']) await buyer.getByLabel(new RegExp('^' + code)).check();
  await buyer.getByRole('button', { name: 'Create RFQ' }).click();
  await buyer.getByRole('heading', { level: 1, name: /^RFQ RFQ-/ }).waitFor();
  const rfqID = await idFromHash(buyer);
  await act(buyer, 'Issue to suppliers', 'Issue to suppliers: done');
  const quotes = [['ABC-STEEL', 'Q-A', '84500', '940'], ['HABESHA-CEMENT', 'Q-B', '86000', '930'], ['SAFARI-BUILD', 'Q-C', '90000', '980']];
  for (const [code, ref, steel, cement] of quotes) {
    await buyer.getByRole('link', { name: 'Record a quote' }).click();
    await buyer.getByLabel('Unit price, line 1').waitFor();
    await selectByText(buyer.getByLabel('Supplier', { exact: true }), code);
    await buyer.getByLabel('Supplier reference').fill(ref);
    await buyer.getByLabel('Unit price, line 1').fill(steel);
    await buyer.getByLabel('Unit price, line 2').fill(cement);
    await buyer.getByRole('button', { name: 'Record quote' }).click();
    await buyer.getByRole('heading', { level: 1, name: /^RFQ RFQ-/ }).waitFor();
  }
  log('rfq issued, 3 quotes recorded');

  // ---- 4. Technical evaluation by the site engineer ----------------------------
  await nav(se, '#/list/rfq_quote/PENDING', 'Quotes');
  for (const [code, , , , ok] of [[...quotes[0], true], [...quotes[1], true], [...quotes[2], false]]) {
    await nav(se, '#/list/rfq_quote/PENDING', 'Quotes');
    await se.getByRole('link', { name: code, exact: true }).click();
    await se.getByRole('heading', { level: 1, name: 'Quote' }).waitFor();
    await se.getByLabel(ok ? 'Compliant' : 'Not compliant', { exact: true }).check();
    await se.getByLabel('Evaluation note').fill(ok ? 'Mill certificates provided' : 'No mill test certificates');
    await act(se, 'Record evaluation', 'Record evaluation: done');
  }

  // ---- 5. Award (lowest compliant) and purchase order --------------------------
  const pmgr = await as('procMgr');
  await nav(pmgr, `#/doc/rfq/${rfqID}`, /^RFQ RFQ-/);
  await selectByText(pmgr.getByLabel('Winning quote (technically compliant only)'), 'Q-A');
  await act(pmgr, 'Award', 'Award: done');
  await nav(buyer, `#/doc/rfq/${rfqID}`, /^RFQ RFQ-/);
  await buyer.getByRole('link', { name: 'Create purchase order' }).click();
  await buyer.getByLabel('Expense or asset account, line 1').waitFor();
  await selectByText(buyer.getByLabel('Expense or asset account, line 1'), '5000');
  await selectByText(buyer.getByLabel('Expense or asset account, line 2'), '5000');
  await buyer.getByRole('button', { name: 'Create purchase order' }).click();
  await buyer.getByRole('heading', { level: 1, name: /^Purchase order PO-/ }).waitFor();
  const poID = await idFromHash(buyer);
  await nav(pmgr, `#/doc/purchase_order/${poID}`, /^Purchase order PO-/);
  await act(pmgr, 'Approve', 'Approve: done');
  await snap(pmgr, 'purchase-order-approved');
  log('purchase order approved');

  // ---- 6. Two partial receipts: storekeeper records, site engineer confirms -----
  const store = await as('store');
  const receipt = async (qty1, qty2, dn) => {
    await nav(store, `#/doc/purchase_order/${poID}`, /^Purchase order PO-/);
    await store.getByRole('link', { name: 'Record goods receipt' }).click();
    await store.getByLabel('Received now, line 1').waitFor();
    await store.getByLabel('Delivery note').fill(dn);
    await store.getByLabel('Received now, line 1').fill(qty1);
    if (qty2) await store.getByLabel('Received now, line 2').fill(qty2);
    await store.getByRole('button', { name: 'Record receipt' }).click();
    await store.getByRole('heading', { level: 1, name: /^Goods receipt GRN-/ }).waitFor();
    const id = await idFromHash(store);
    await act(store, 'Submit for approval', 'Submit for approval: done');
    await nav(se, `#/doc/grn/${id}`, /^Goods receipt GRN-/);
    await act(se, 'Confirm receipt', 'draft journal was created');
  };
  await receipt('12', '500', 'DN-4471');
  await receipt('8', '', 'DN-4502');
  log('two receipts confirmed');

  // ---- 7. Invoices: 3-way match, AP supervisor approval -------------------------
  const ap = await as('apClerk');
  const enterInvoice = async (no, q1, q2, p2, tax) => {
    await nav(ap, `#/doc/purchase_order/${poID}`, /^Purchase order PO-/);
    await ap.getByRole('link', { name: 'Enter supplier invoice' }).click();
    await ap.getByLabel('Quantity billed, line 1').waitFor();
    await ap.getByLabel('Invoice number').fill(no);
    await ap.getByLabel('Quantity billed, line 1').fill(q1);
    if (q2) { await ap.getByLabel('Quantity billed, line 2').fill(q2); await ap.getByLabel('Unit price billed, line 2').fill(p2); }
    await ap.getByLabel('Tax (VAT)').fill(tax);
    await ap.getByRole('button', { name: 'Save invoice' }).click();
    await ap.getByRole('heading', { level: 1, name: /^Supplier invoice/ }).waitFor();
    const id = await idFromHash(ap);
    await act(ap, 'Submit for approval', 'Three-way match: MATCHED');
    return id;
  };
  const inv1 = await enterInvoice('ABC/2026/0417', '12', '500', '945', '222975');
  // Separation of duties in the UI: the clerk who entered the invoice also
  // holds the supervisor role here; the server refuses and the UI says why.
  const dual = await as('apDual');
  await nav(dual, `#/doc/supplier_invoice/${inv1}`, /^Supplier invoice/);
  await dual.getByRole('button', { name: 'Approve', exact: true }).click();
  await dual.locator('#alert').filter({ hasText: 'segregation of duties' }).waitFor();
  await snap(dual, 'sod-refusal-shown');
  log('self-approval refused and explained in the UI');
  const sup = await as('apSup');
  await nav(sup, `#/doc/supplier_invoice/${inv1}`, /^Supplier invoice/);
  await act(sup, 'Approve', 'draft journal was created');
  await audit(sup, 'approved invoice with three-way match');
  await snap(sup, 'invoice-approved');
  const inv2 = await enterInvoice('ABC/2026/0431', '8', '', '', '101400');
  await nav(sup, `#/doc/supplier_invoice/${inv2}`, /^Supplier invoice/);
  await act(sup, 'Approve', 'draft journal was created');

  // ---- 8. Finance approves and posts the subledger journals ---------------------
  const fin = await as('finMgr');
  const ctl = await as('controller');
  const batch = async (expectN) => {
    await nav(fin, '#/journals', 'Journals');
    await fin.getByLabel('Select all draft journals').check();
    await fin.getByRole('button', { name: 'Approve selected' }).click();
    await fin.locator('p.notice').filter({ hasText: `${expectN} of ${expectN} journals done` }).waitFor();
    await nav(ctl, '#/journals', 'Journals');
    await ctl.getByLabel('Select all approved journals').check();
    await ctl.getByRole('button', { name: 'Post selected' }).click();
    await ctl.locator('p.notice').filter({ hasText: `${expectN} of ${expectN} journals done` }).waitFor();
  };
  await nav(fin, '#/home', 'My work');
  await audit(fin, 'home (finance manager)');
  await snap(fin, 'finance-my-work');
  await batch(4);
  log('4 subledger journals approved and posted');

  // ---- 9. Payments: prepare, dual approval with MFA, release by another officer --
  const tr = await as('treasury');
  const tr2 = await as('treasury2');
  const cfo = await as('cfo');
  const payIDs = [];
  const pay = async (invID) => {
    await nav(tr, `#/doc/supplier_invoice/${invID}`, /^Supplier invoice/);
    await tr.getByRole('link', { name: 'Prepare payment' }).click();
    const payee = tr.getByLabel('Pay to (approved account)');
    await payee.locator('option').first().waitFor({ state: 'attached' });
    await tr.getByRole('button', { name: 'Create payment instruction' }).click();
    await tr.getByRole('heading', { level: 1, name: /^Payment instruction PAY-/ }).waitFor();
    const id = await idFromHash(tr);
    const number = (await h1(tr)).replace('Payment instruction ', '');
    await act(tr, 'Submit for approval', 'Submit for approval: done');
    await nav(fin, `#/doc/payment_instruction/${id}`, /^Payment instruction/);
    await act(fin, 'Approve', 'Status: PARTIALLY_APPROVED');
    await nav(cfo, `#/doc/payment_instruction/${id}`, /^Payment instruction/);
    await act(cfo, 'Approve', 'Status: APPROVED');
    // The preparer sees Release (holds the permission) but the database refuses.
    await nav(tr, `#/doc/payment_instruction/${id}`, /^Payment instruction/);
    await tr.getByRole('button', { name: 'Release payment', exact: true }).click();
    await tr.locator('#alert').filter({ hasText: 'cannot release' }).waitFor();
    await nav(tr2, `#/doc/payment_instruction/${id}`, /^Payment instruction/);
    await act(tr2, 'Release payment', 'draft journal was created');
    payIDs.push(id);
    return number;
  };
  const pay1 = await pay(inv1);
  await snap(tr2, 'payment-released');
  const pay2 = await pay(inv2);
  await batch(2);
  log('payments', pay1, pay2, 'released and posted');

  // ---- IA-040-01: entity-level finance documents and bank details --------------
  await nav(se, `#/doc/payment_instruction/${payIDs[0]}`);
  await se.locator('#alert').filter({ hasText: 'Not found.' }).waitFor();
  await nav(se, '#/list/payment_instruction', 'Payments');
  await se.getByRole('table').filter({ hasText: 'Payments (0)' }).waitFor();
  await nav(fin, '#/list/supplier_bank_account', 'Supplier bank accounts');
  await fin.getByRole('link').filter({ hasText: /^[0-9a-f]{8}$/ }).first().click();
  await fin.getByRole('heading', { level: 1, name: 'Supplier bank account' }).waitFor();
  const shown = await fin.locator('#view').innerText();
  if (shown.includes('1000123456789') || !shown.includes('****6789')) fail(`supplier bank page not masked: ${shown.slice(0, 200)}`);
  await fin.getByLabel('Purpose of the reveal').fill('Call-back verification of payee details with the supplier');
  await fin.getByRole('button', { name: 'Reveal full account number' }).click();
  await fin.locator('output.reveal').filter({ hasText: '1000123456789' }).waitFor();
  await audit(fin, 'supplier bank account with reveal');
  log('IA-040-01: payment hidden from site engineer; bank number masked; audited reveal works');

  // ---- 10. Bank statement import (independent officer) and reconciliation -------
  const bo = await as('bankOfficer');
  await nav(bo, '#/bank', 'Bank statements');
  const today = new Date().toISOString().slice(0, 10);
  const statement = JSON.stringify({ company_bank_id: FX.bank, statement_no: 'CBE-2026-10-UI', statement_date: today,
    opening_balance: '50000000', closing_balance: '47812600', lines: [
      { booking_date: today, amount: '-1709475', reference: `TRF ${pay1} ABC STEEL`, counterparty: 'ABC STEEL PLC' },
      { booking_date: today, amount: '300000', reference: 'CUSTOMER RECEIPT IPC-07', counterparty: 'MINISTRY OF ROADS' },
      { booking_date: today, amount: '-777400', reference: `${pay2}/ABC`, counterparty: 'ABC STEEL PLC' },
      { booking_date: today, amount: '-525', reference: 'SERVICE CHARGE', counterparty: 'CBE' }] });
  await bo.getByLabel('Statement file').setInputFiles({ name: 'cbe-2026-10-ui.json', mimeType: 'application/json', buffer: Buffer.from(statement) });
  await bo.getByRole('table').filter({ hasText: 'SERVICE CHARGE' }).waitFor();
  await audit(bo, 'bank statement import with preview');
  await bo.getByRole('button', { name: 'Import statement' }).click();
  await bo.locator('p.notice').filter({ hasText: 'Statement imported' }).waitFor();
  const acc = await as('accountant', { colorScheme: 'dark' });
  await nav(acc, '#/bank', 'Bank statements');
  await acc.getByRole('button', { name: 'Reconcile statement CBE-2026-10-UI' }).click();
  await acc.locator('p.notice').filter({ hasText: '2 matched, 2 left for investigation' }).waitFor();
  await audit(acc, 'reconciliation result (dark theme)');
  await snap(acc, 'bank-reconciled-dark');
  await batch(2);
  log('statement imported and reconciled; settlement journals posted');

  // ---- 11. Reports -----------------------------------------------------------------
  await nav(ctl, '#/recon', 'Reconciliation');
  await ctl.locator('p.notice').filter({ hasText: 'Every subledger agrees with the general ledger.' }).waitFor();
  if (await ctl.locator('tr.diff').count()) fail('reconciliation shows differences');
  await audit(ctl, 'reconciliation report');
  await snap(ctl, 'subledger-gl-reconciliation');
  await nav(pm, '#/cost', 'Project cost report');
  const row = pm.getByRole('row').filter({ hasText: '01-MAT' });
  await row.waitFor();
  const cells = await row.getByRole('cell').allTextContents();
  const want = ['01-MAT', '12,100,000.00', '2,160,000.00', '0.00', '2,160,000.00', '2,162,500.00', '2,162,500.00', '9,937,500.00'];
  if (JSON.stringify(cells) !== JSON.stringify(want)) fail(`cost report row ${JSON.stringify(cells)} != ${JSON.stringify(want)}`);
  await snap(pm, 'project-cost-report');

  // ---- 12. Phone width: no horizontal page scroll ------------------------------------
  const mobile = await as('pmMobile', { viewport: { width: 390, height: 844 } });
  await nav(mobile, '#/cost', 'Project cost report');
  await mobile.getByRole('row').filter({ hasText: '01-MAT' }).waitFor();
  await audit(mobile, 'cost report at 390px');
  await nav(mobile, `#/doc/purchase_order/${poID}`, /^Purchase order/);
  await audit(mobile, 'purchase order at 390px');
  await snap(mobile, 'mobile-purchase-order');

  // ---- 13. Sign-out revokes the session server-side ------------------------------------
  await ctl.getByRole('button', { name: 'Sign out' }).click();
  await ctl.getByRole('heading', { level: 1, name: 'Sign in' }).waitFor();
  const r = await fetch(process.env.SERK_URL + '/v1/identity/me', { headers: { Authorization: 'Bearer ' + T.controller } });
  if (r.status !== 401) fail(`token still valid after sign-out: ${r.status}`);
  else log('sign-out revoked the session (401 afterwards)');
} catch (e) {
  fail(`journey aborted: ${e.message.split('\n')[0]}`);
  for (const [role, p] of Object.entries(pages)) {
    try { await snap(p, `failure-${role}`); } catch { /* page may be gone */ }
  }
} finally {
  await browser.close();
}

if (failures.length) {
  console.log(`\n${failures.length} failure(s):\n- ` + failures.join('\n- '));
  process.exit(1);
}
console.log('\nCONSOLE JOURNEY A: PASS');
