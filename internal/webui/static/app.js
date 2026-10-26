// SERK operations console (Journey A: procure-to-pay).
//
// Security model: this page holds no authority. The access token lives only
// in memory (never in storage); every action is an API call that the kernel
// and PostgreSQL re-authorize, including separation of duties, project scope,
// MFA step-up and budget checks. Server data is only ever inserted as text
// (no innerHTML), under a CSP that forbids inline script.

const S = { token: null, me: null, ref: null, can: new Set() };

// ---------- DOM helpers ----------
function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k === 'on') for (const [ev, fn] of Object.entries(v)) el.addEventListener(ev, fn);
    else if (k === 'value') el.value = v;
    else el.setAttribute(k, v === true ? '' : String(v));
  }
  for (const c of kids.flat(Infinity)) {
    if (c == null || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}
const $ = (id) => document.getElementById(id);
let uid = 0;
const nextId = (p) => `${p}-${++uid}`;

function field(label, control, hint) {
  const id = control.id || (control.id = nextId('f'));
  const kids = [h('label', { for: id }, label), control];
  if (hint) {
    const hid = nextId('h');
    control.setAttribute('aria-describedby', hid);
    kids.push(h('span', { class: 'hint', id: hid }, hint));
  }
  return h('div', { class: 'field' }, kids);
}
const input = (name, attrs = {}) => h('input', { name, ...attrs });
function select(name, options, attrs = {}) {
  const s = h('select', { name, ...attrs });
  for (const o of options) s.append(h('option', { value: o.value }, o.label));
  return s;
}

function say(msg) { const s = $('status'); s.textContent = ''; setTimeout(() => { s.textContent = msg; }, 30); }
function showError(err) {
  const a = $('alert');
  a.textContent = '';
  a.append(h('strong', {}, errorTitle(err)), ' ', err.message || String(err));
  a.hidden = false;
  a.scrollIntoView({ block: 'nearest' });
}
function clearError() { $('alert').hidden = true; }
function errorTitle(e) {
  if (!(e instanceof ApiError)) return 'Something went wrong.';
  if (e.status === 401 && /insufficient_user_authentication/.test(e.challenge || '')) return 'Multi-factor sign-in required.';
  if (e.status === 401) return 'Your session is no longer valid.';
  if (e.status === 403) return 'Not permitted.';
  if (e.status === 404) return 'Not found.';
  if (e.status === 409) return 'Refused by a business rule.';
  if (e.status === 422 || e.status === 400) return 'Please correct the input.';
  if (e.status === 429) return 'Too many requests; wait a moment.';
  return 'The server could not complete the request.';
}

// ---------- API ----------
class ApiError extends Error {
  constructor(status, code, message, challenge) { super(message); this.status = status; this.code = code; this.challenge = challenge; }
}
async function api(method, path, body, raw) {
  const init = { method, headers: { Authorization: 'Bearer ' + S.token } };
  if (raw !== undefined) { init.headers['Content-Type'] = 'application/json'; init.body = raw; }
  else if (body !== undefined) { init.headers['Content-Type'] = 'application/json'; init.body = JSON.stringify(body); }
  const r = await fetch(path, init);
  let data = null;
  try { data = await r.json(); } catch { /* empty body */ }
  if (!r.ok) {
    const e = (data && data.error) || {};
    throw new ApiError(r.status, e.code || 'error', e.message || r.statusText, r.headers.get('WWW-Authenticate'));
  }
  return data;
}

// ---------- formatting & exact decimals ----------
function money(s) {
  if (s == null || s === '') return '';
  s = String(s);
  const neg = s.startsWith('-');
  if (neg) s = s.slice(1);
  let [i, f = ''] = s.split('.');
  f = f.replace(/0+$/, '');
  f = (f + '00').slice(0, Math.max(2, f.length));
  i = i.replace(/\B(?=(\d{3})+(?!\d))/g, ',');
  return (neg ? '−' : '') + i + '.' + f;
}
const SC = 1000000n; // 6 decimal places, as stored
function dparse(s) {
  s = String(s ?? '').trim();
  if (!/^-?\d+(\.\d{1,6})?$/.test(s)) return null;
  const neg = s[0] === '-';
  if (neg) s = s.slice(1);
  const [i, f = ''] = s.split('.');
  const v = BigInt(i) * SC + BigInt(f.padEnd(6, '0'));
  return neg ? -v : v;
}
function dfmt(v) {
  const neg = v < 0n;
  if (neg) v = -v;
  let f = (v % SC).toString().padStart(6, '0').replace(/0+$/, '');
  if (f.length < 2) f = f.padEnd(2, '0');
  return (neg ? '-' : '') + (v / SC).toString() + '.' + f;
}
const dmul = (a, b) => (a * b) / SC;
const when = (s) => (s ? new Date(s).toLocaleString() : '');
const words = (k) => k.replace(/_/g, ' ').replace(/^./, (c) => c.toUpperCase());

const OK = /^(APPROVED|ACTIVE|CONFIRMED|SETTLED|MATCHED|RECONCILED|POSTED|COMPLIANT|AWARDED)/;
const BAD = /^(REJECTED|CANCELLED|BLOCKED|EXCEPTION|NON_COMPLIANT|REVOKED|CLOSED)/;
function chip(status) {
  const cls = OK.test(status) ? 'chip ok' : BAD.test(status) ? 'chip bad' : 'chip warn';
  return h('span', { class: cls }, String(status).replace(/_/g, ' '));
}

// ---------- document catalogue ----------
// actions: [action, permission, mode]; mode: undefined | 'opt' (optional
// reason) | 'req' (reason required) | 'award' | 'evaluate'.
const DOCS = {
  boq_version: { title: 'BOQ versions', one: 'BOQ version', base: '/v1/boqs', create: 'boq.manage', form: 'boq',
    statuses: ['DRAFT', 'SUBMITTED', 'APPROVED', 'REJECTED', 'SUPERSEDED'],
    actions: { DRAFT: [['submit', 'boq.manage']], SUBMITTED: [['approve', 'boq.approve', 'opt'], ['reject', 'boq.approve', 'req']] } },
  purchase_requisition: { title: 'Requisitions', one: 'Requisition', base: '/v1/requisitions', create: 'pr.create', form: 'requisition',
    statuses: ['DRAFT', 'SUBMITTED', 'APPROVED', 'REJECTED'],
    actions: { DRAFT: [['submit', 'pr.create']], SUBMITTED: [['approve', 'pr.approve', 'opt'], ['reject', 'pr.approve', 'req']] } },
  rfq: { title: 'RFQs', one: 'RFQ', base: '/v1/rfqs', create: 'rfq.manage', form: 'rfq',
    statuses: ['DRAFT', 'ISSUED', 'AWARDED', 'CANCELLED'],
    actions: { DRAFT: [['issue', 'rfq.manage']], ISSUED: [['award', 'rfq.award', 'award']] } },
  rfq_quote: { title: 'Quotes', one: 'Quote', base: '/v1/quotes', create: 'rfq.manage', form: 'quote',
    statuses: ['PENDING', 'COMPLIANT', 'NON_COMPLIANT'],
    actions: { PENDING: [['evaluate', 'rfq.evaluate', 'evaluate']] } },
  purchase_order: { title: 'Purchase orders', one: 'Purchase order', base: '/v1/purchase-orders', create: 'po.manage', form: 'po',
    statuses: ['DRAFT', 'APPROVED', 'CLOSED', 'CANCELLED'],
    actions: { DRAFT: [['approve', 'po.approve', 'opt']] } },
  grn: { title: 'Goods receipts', one: 'Goods receipt', base: '/v1/goods-receipts', create: 'grn.create', form: 'grn',
    statuses: ['DRAFT', 'SUBMITTED', 'CONFIRMED'],
    actions: { DRAFT: [['submit', 'grn.create']], SUBMITTED: [['confirm', 'grn.confirm']] } },
  supplier_invoice: { title: 'Supplier invoices', one: 'Supplier invoice', base: '/v1/invoices', create: 'ap.enter', form: 'invoice',
    statuses: ['DRAFT', 'SUBMITTED', 'APPROVED', 'REJECTED'],
    actions: { DRAFT: [['submit', 'ap.enter']], SUBMITTED: [['approve', 'ap.approve', 'opt'], ['reject', 'ap.approve', 'req']] } },
  payment_instruction: { title: 'Payments', one: 'Payment instruction', base: '/v1/payments', create: 'payment.prepare', form: 'payment',
    statuses: ['DRAFT', 'SUBMITTED', 'PARTIALLY_APPROVED', 'APPROVED', 'RELEASED', 'SETTLED', 'CANCELLED'],
    actions: {
      DRAFT: [['submit', 'payment.prepare'], ['cancel', 'payment.prepare', 'req']],
      SUBMITTED: [['approve', 'payment.approve'], ['cancel', 'payment.approve', 'req']],
      PARTIALLY_APPROVED: [['approve', 'payment.approve'], ['cancel', 'payment.approve', 'req']],
      APPROVED: [['release', 'payment.release'], ['cancel', 'payment.approve', 'req']] } },
  supplier: { title: 'Suppliers', one: 'Supplier', base: '/v1/suppliers', create: 'supplier.manage', form: 'supplier',
    statuses: ['PENDING', 'ACTIVE', 'BLOCKED'],
    actions: { PENDING: [['approve', 'supplier.approve']], ACTIVE: [['block', 'supplier.approve', 'req']] } },
  supplier_bank_account: { title: 'Supplier bank accounts', one: 'Supplier bank account', base: '/v1/supplier-bank-accounts', create: 'supplier.manage', form: 'supplierbank',
    statuses: ['PENDING', 'APPROVED', 'REVOKED'], actions: { PENDING: [['approve', 'supplier.bank.approve']] } },
  company_bank_account: { title: 'Company bank accounts', one: 'Company bank account', base: '/v1/company-bank-accounts', create: 'bankacct.manage', form: 'companybank',
    statuses: ['PENDING', 'ACTIVE', 'CLOSED'], actions: { PENDING: [['approve', 'bankacct.approve']] } },
  p2p_policy: { title: 'P2P policies', one: 'P2P policy', base: '/v1/p2p/policies', create: 'p2p.policy.manage', form: 'policy',
    statuses: ['DRAFT', 'APPROVED', 'REJECTED', 'RETIRED'],
    actions: { DRAFT: [['approve', 'p2p.policy.approve'], ['reject', 'p2p.policy.approve']] } },
  // Contract to cash (Journey B).
  customer: { title: 'Customers', one: 'Customer', base: '/v1/customers', create: 'customer.manage', form: 'customer',
    statuses: ['PENDING', 'ACTIVE', 'BLOCKED'], actions: { PENDING: [['approve', 'customer.approve']] } },
  contract_policy: { title: 'Contract policies', one: 'Contract policy', base: '/v1/contract-policies', create: 'contract.policy.manage', form: 'contractpolicy',
    statuses: ['DRAFT', 'APPROVED', 'REJECTED', 'RETIRED'],
    actions: { DRAFT: [['approve', 'contract.policy.approve'], ['reject', 'contract.policy.approve']] } },
  contract: { title: 'Contracts', one: 'Contract', base: '/v1/contracts', create: 'contract.manage', form: 'contract',
    statuses: ['DRAFT', 'SUBMITTED', 'ACTIVE', 'REJECTED', 'CLOSED'],
    actions: { DRAFT: [['submit', 'contract.manage']], SUBMITTED: [['approve', 'contract.approve', 'opt'], ['reject', 'contract.approve', 'req']] } },
  measurement: { title: 'Measurements', one: 'Measurement', base: '/v1/measurements', create: 'measure.create', form: 'measurement',
    statuses: ['DRAFT', 'SUBMITTED', 'VERIFIED', 'REJECTED'],
    actions: { DRAFT: [['submit', 'measure.create']], SUBMITTED: [['verify', 'measure.verify'], ['reject', 'measure.verify', 'req']] } },
  ipc: { title: 'Payment certificates', one: 'Payment certificate', base: '/v1/ipcs', create: 'ipc.prepare', form: 'ipc',
    statuses: ['DRAFT', 'SUBMITTED', 'CERTIFIED', 'INVOICED', 'REJECTED', 'CANCELLED'],
    actions: {
      DRAFT: [['submit', 'ipc.prepare'], ['cancel', 'ipc.prepare', 'req']],
      SUBMITTED: [['certify', 'ipc.certify', 'certify'], ['reject', 'ipc.certify', 'req'], ['cancel', 'ipc.prepare', 'req']],
      CERTIFIED: [['invoice', 'ar.invoice.create', 'invoice']] } },
  customer_invoice: { title: 'Customer invoices', one: 'Customer invoice', base: '/v1/customer-invoices',
    statuses: ['DRAFT', 'APPROVED'], actions: { DRAFT: [['approve', 'ar.invoice.approve']] } },
  customer_receipt: { title: 'Receipts', one: 'Receipt', base: '/v1/receipts', create: 'ar.receipt.create', form: 'receipt',
    statuses: ['DRAFT', 'CONFIRMED', 'CANCELLED'], actions: { DRAFT: [['confirm', 'ar.receipt.confirm'], ['cancel', 'ar.receipt.create', 'req'], ['cancel', 'ar.receipt.confirm', 'req']] } },
  contract_variation: { title: 'Variations', one: 'Variation', base: '/v1/variations',
    statuses: ['DRAFT', 'SUBMITTED', 'APPROVED', 'REJECTED', 'CANCELLED'],
    actions: { DRAFT: [['submit', 'contract.manage'], ['cancel', 'contract.manage', 'req']],
      SUBMITTED: [['approve', 'contract.approve'], ['reject', 'contract.approve', 'req'], ['cancel', 'contract.manage', 'req']] } },
  customer_credit_note: { title: 'Credit notes', one: 'Credit note', base: '/v1/credit-notes',
    statuses: ['DRAFT', 'APPROVED', 'CANCELLED'],
    actions: { DRAFT: [['approve', 'ar.credit.approve'], ['cancel', 'ar.credit.create', 'req'], ['cancel', 'ar.credit.approve', 'req']] } },
  retention_release: { title: 'Retention releases', one: 'Retention release', base: '/v1/retention-releases',
    statuses: ['DRAFT', 'APPROVED', 'CANCELLED'],
    actions: { DRAFT: [['approve', 'ar.retention.approve'], ['cancel', 'ar.retention.create', 'req'], ['cancel', 'ar.retention.approve', 'req']] } },
  // Stock (Journey C).
  stock_item: { title: 'Stock items', one: 'Stock item', base: '/v1/stock-items', create: 'stock.item.manage', form: 'stockitem',
    statuses: ['PENDING', 'ACTIVE'], actions: { PENDING: [['approve', 'stock.item.approve']] } },
  warehouse: { title: 'Warehouses', one: 'Warehouse', create: 'warehouse.manage', form: 'warehouse', statuses: ['ACTIVE'], actions: {} },
  stock_receipt: { title: 'Put-aways', one: 'Put-away', statuses: ['POSTED'], actions: {} },
  stock_issue: { title: 'Stock issues', one: 'Stock issue', base: '/v1/stock-issues', create: 'stock.issue', form: 'stockissue',
    statuses: ['DRAFT', 'APPROVED', 'REJECTED', 'CANCELLED'],
    actions: { DRAFT: [['approve', 'stock.issue.approve'], ['reject', 'stock.issue.approve', 'req'], ['cancel', 'stock.issue', 'req']] } },
  stock_count: { title: 'Stock counts', one: 'Stock count', base: '/v1/stock-counts', create: 'stock.count', form: 'stockcount',
    statuses: ['DRAFT', 'APPROVED', 'REJECTED'], actions: { DRAFT: [['approve', 'stock.adjust.approve'], ['reject', 'stock.adjust.approve', 'req']] } },
  stock_transfer: { title: 'Stock transfers', one: 'Stock transfer', base: '/v1/stock-transfers', create: 'stock.transfer', form: 'stocktransfer',
    statuses: ['DRAFT', 'APPROVED', 'REJECTED', 'CANCELLED'],
    actions: { DRAFT: [['approve', 'stock.transfer.approve'], ['reject', 'stock.transfer.approve', 'req'], ['cancel', 'stock.transfer', 'req']] } },
  schedule_version: { title: 'Schedules', one: 'Schedule', base: '/v1/schedules', create: 'schedule.manage', form: 'schedule',
    statuses: ['DRAFT', 'SUBMITTED', 'BASELINE', 'REJECTED', 'SUPERSEDED'],
    actions: { DRAFT: [['submit', 'schedule.manage']], SUBMITTED: [['approve', 'schedule.approve'], ['reject', 'schedule.approve', 'req']] } },
  schedule_progress: { title: 'Progress reports', one: 'Progress report', base: '/v1/progress', create: 'schedule.manage', form: 'progress',
    statuses: ['DRAFT', 'APPROVED', 'REJECTED'], actions: { DRAFT: [['approve', 'schedule.approve'], ['reject', 'schedule.approve', 'req']] } },
  // Site operations (0037): diaries prepared online or on a field device.
  site_diary: { title: 'Site diaries', one: 'Site diary', base: '/v1/site/diaries', create: 'site.diary.manage', form: 'diary',
    statuses: ['DRAFT', 'SUBMITTED', 'APPROVED', 'REJECTED', 'CANCELLED'],
    actions: { DRAFT: [['submit', 'site.diary.manage'], ['cancel', 'site.diary.manage', 'req'], ['reject', 'site.diary.approve', 'req']],
      SUBMITTED: [['approve', 'site.diary.approve'], ['reject', 'site.diary.approve', 'req']] } },
  money_in: { title: 'Money received', one: 'Money received', statuses: ['UNAPPLIED', 'RECORDED'], actions: {},
    link: (d) => (d.status === 'UNAPPLIED' && S.can.has('ar.receipt.create') ? `#/new/receipt/${d.id}` : null) },
};
const ACTION_LABEL = { submit: 'Submit for approval', approve: 'Approve', reject: 'Reject', issue: 'Issue to suppliers', award: 'Award',
  evaluate: 'Record evaluation', confirm: 'Confirm receipt', release: 'Release payment', cancel: 'Cancel', block: 'Block supplier',
  verify: 'Verify measurement', certify: 'Certify', invoice: 'Issue customer invoice' };

const NAV = [
  ['Overview', [['#/home', 'My work', null], ['#/ask', 'Ask', 'intelligence.read'], ['#/risk', 'Risks', 'intelligence.read'], ['#/reports', 'Reports', null]]],
  ['Project', [['#/list/boq_version', 'BOQ', 'p2p.read'], ['#/list/purchase_requisition', 'Requisitions', 'p2p.read'], ['#/cost', 'Cost report', 'p2p.read']]],
  ['Planning', [['#/list/schedule_version', 'Schedules', 'p2p.read'], ['#/list/schedule_progress', 'Progress', 'p2p.read'], ['#/evm', 'Earned value', 'p2p.read']]],
  ['Procurement', [['#/list/rfq', 'RFQs', 'p2p.read'], ['#/list/rfq_quote', 'Quotes', 'p2p.read'], ['#/list/purchase_order', 'Purchase orders', 'p2p.read'], ['#/list/supplier', 'Suppliers', 'p2p.read']]],
  ['Site', [['#/list/site_diary', 'Site diaries', 'p2p.read'], ['#/site/devices', 'Field devices', 'site.device.register|site.device.manage'],
    ['#/list/grn', 'Goods receipts', 'p2p.read']]],
  ['Stores', [['#/stock', 'Stock on hand', 'p2p.read'], ['#/list/stock_issue', 'Stock issues', 'p2p.read'], ['#/list/stock_count', 'Stock counts', 'p2p.read'],
    ['#/list/stock_transfer', 'Transfers', 'p2p.read'],
    ['#/list/stock_receipt', 'Put-aways', 'p2p.read'], ['#/list/stock_item', 'Stock items', 'p2p.read'], ['#/list/warehouse', 'Warehouses', 'p2p.read']]],
  ['Payables', [['#/list/supplier_invoice', 'Invoices', 'p2p.read'], ['#/list/payment_instruction', 'Payments', 'p2p.read']]],
  ['Treasury', [['#/bank', 'Bank statements', 'bank.import|bank.reconcile'], ['#/list/company_bank_account', 'Company banks', 'scope.tenant_wide'], ['#/list/supplier_bank_account', 'Supplier banks', 'p2p.read']]],
  ['Revenue', [['#/list/contract', 'Contracts', 'p2p.read'], ['#/list/contract_variation', 'Variations', 'p2p.read'], ['#/list/measurement', 'Measurements', 'p2p.read'], ['#/list/ipc', 'Payment certificates', 'p2p.read'],
    ['#/list/customer_invoice', 'Customer invoices', 'p2p.read'], ['#/list/customer_credit_note', 'Credit notes', 'p2p.read'],
    ['#/list/retention_release', 'Retention releases', 'p2p.read'], ['#/list/money_in', 'Money received', 'ar.receipt.create|ar.receipt.confirm'],
    ['#/list/customer_receipt', 'Receipts', 'scope.tenant_wide'], ['#/list/customer', 'Customers', 'p2p.read']]],
  ['Finance', [['#/journals', 'Journals', 'journal.read'], ['#/recon', 'Reconciliation', 'journal.read'], ['#/tb', 'Trial balance', 'journal.read'],
    ['#/aging/ap', 'Payables aging', 'scope.tenant_wide'], ['#/aging/ar', 'Receivables aging', 'scope.tenant_wide'], ['#/list/p2p_policy', 'P2P policies', 'scope.tenant_wide'],
    ['#/list/contract_policy', 'Contract policies', 'scope.tenant_wide'], ['#/controls', 'Control review', 'scope.tenant_wide']]],
  ['Company', [['#/automation', 'Automation rules', 'automation.manage|automation.activate|workflow.read'], ['#/settings', 'Company settings', null]]],
];
const allowed = (perm) => !perm || perm.split('|').some((p) => S.can.has(p));

const QUEUES = [
  ['boq.approve', 'boq_version', 'SUBMITTED', 'BOQs to approve'],
  ['pr.approve', 'purchase_requisition', 'SUBMITTED', 'Requisitions to approve'],
  ['rfq.manage', 'purchase_requisition', 'APPROVED', 'Approved requisitions'],
  ['rfq.manage', 'rfq', 'DRAFT', 'RFQs to issue'],
  ['rfq.evaluate', 'rfq_quote', 'PENDING', 'Quotes to evaluate'],
  ['rfq.award', 'rfq', 'ISSUED', 'RFQs awaiting award'],
  ['po.manage', 'rfq', 'AWARDED', 'Awarded RFQs'],
  ['po.approve', 'purchase_order', 'DRAFT', 'Purchase orders to approve'],
  ['grn.create', 'purchase_order', 'APPROVED', 'Open purchase orders'],
  ['grn.create', 'grn', 'DRAFT', 'Receipts to submit'],
  ['grn.confirm', 'grn', 'SUBMITTED', 'Receipts to confirm'],
  ['ap.enter', 'supplier_invoice', 'DRAFT', 'Invoices to submit'],
  ['ap.approve', 'supplier_invoice', 'SUBMITTED', 'Invoices to approve'],
  ['payment.prepare', 'payment_instruction', 'DRAFT', 'Payments to submit'],
  ['payment.approve', 'payment_instruction', 'SUBMITTED', 'Payments to approve'],
  ['payment.approve', 'payment_instruction', 'PARTIALLY_APPROVED', 'Payments needing 2nd approval'],
  ['payment.release', 'payment_instruction', 'APPROVED', 'Payments to release'],
  ['supplier.approve', 'supplier', 'PENDING', 'Suppliers to approve'],
  ['supplier.bank.approve', 'supplier_bank_account', 'PENDING', 'Supplier bank accounts to approve'],
  ['bankacct.approve', 'company_bank_account', 'PENDING', 'Company bank accounts to approve'],
  ['p2p.policy.approve', 'p2p_policy', 'DRAFT', 'Policies to approve'],
  ['bank.reconcile', 'bank_statement', 'OPEN', 'Statements to reconcile'],
  ['customer.approve', 'customer', 'PENDING', 'Customers to approve'],
  ['contract.policy.approve', 'contract_policy', 'DRAFT', 'Contract policies to approve'],
  ['contract.approve', 'contract', 'SUBMITTED', 'Contracts to approve'],
  ['contract.manage', 'contract_variation', 'DRAFT', 'Variations to submit'],
  ['contract.approve', 'contract_variation', 'SUBMITTED', 'Variations to approve'],
  ['measure.create', 'measurement', 'DRAFT', 'Measurements to submit'],
  ['measure.verify', 'measurement', 'SUBMITTED', 'Measurements to verify'],
  ['ipc.prepare', 'ipc', 'DRAFT', 'Certificates to submit'],
  ['ipc.certify', 'ipc', 'SUBMITTED', 'Certificates to certify'],
  ['ar.invoice.create', 'ipc', 'CERTIFIED', 'Certified IPCs to invoice'],
  ['ar.invoice.approve', 'customer_invoice', 'DRAFT', 'Customer invoices to approve'],
  ['ar.credit.approve', 'customer_credit_note', 'DRAFT', 'Credit notes to approve'],
  ['ar.retention.approve', 'retention_release', 'DRAFT', 'Retention releases to approve'],
  ['ar.receipt.create', 'money_in', 'UNAPPLIED', 'Money received to apply'],
  ['ar.receipt.confirm', 'customer_receipt', 'DRAFT', 'Receipts to confirm'],
  ['schedule.manage', 'schedule_version', 'DRAFT', 'Schedules to submit'],
  ['schedule.approve', 'schedule_version', 'SUBMITTED', 'Schedules to approve'],
  ['schedule.approve', 'schedule_progress', 'DRAFT', 'Progress reports to approve'],
  ['site.diary.manage', 'site_diary', 'DRAFT', 'Site diaries to submit'],
  ['site.diary.approve', 'site_diary', 'SUBMITTED', 'Site diaries to approve'],
  ['stock.item.approve', 'stock_item', 'PENDING', 'Stock items to approve'],
  ['stock.receive', 'grn', 'CONFIRMED', 'Goods receipts to put away'],
  ['stock.issue.approve', 'stock_issue', 'DRAFT', 'Stock issues to approve'],
  ['stock.adjust.approve', 'stock_count', 'DRAFT', 'Stock counts to approve'],
  ['stock.transfer.approve', 'stock_transfer', 'DRAFT', 'Stock transfers to approve'],
];

// ---------- shell ----------
function page(title, lede, ...kids) {
  const v = $('view');
  v.textContent = '';
  const h1 = h('h1', { tabindex: '-1' }, title);
  v.append(...[h1, lede ? h('p', { class: 'lede' }, lede) : null, ...kids].filter(Boolean));
  document.title = `${title} — SERK Construction`;
  h1.focus();
  return v;
}
function buildNav() {
  const nav = $('nav');
  nav.textContent = '';
  // Phones: the menu folds away behind one button.
  const tog = h('button', { type: 'button', class: 'ghost navtoggle', 'aria-expanded': 'false', 'aria-controls': 'nav' }, 'Menu');
  tog.addEventListener('click', () => { const o = nav.classList.toggle('open'); tog.setAttribute('aria-expanded', String(o)); });
  nav.addEventListener('click', (e) => { if (e.target.closest('a')) { nav.classList.remove('open'); tog.setAttribute('aria-expanded', 'false'); } });
  nav.append(tog);
  for (const [group, items] of NAV) {
    const vis = items.filter(([, , p]) => allowed(p));
    if (!vis.length) continue;
    nav.append(h('h2', {}, group), h('ul', {}, vis.map(([href, label]) => h('li', {}, h('a', { href }, label)))));
  }
  nav.hidden = false;
}
function markNav() {
  const cur = location.hash.split('/').slice(0, 3).join('/');
  for (const a of $('nav').querySelectorAll('a')) {
    if (a.getAttribute('href') === cur || (cur.startsWith('#/doc/') && a.getAttribute('href') === '#/list/' + location.hash.split('/')[2])) a.setAttribute('aria-current', 'page');
    else a.removeAttribute('aria-current');
  }
}

async function route() {
  clearError();
  if (!S.token) return renderSignin();
  markNav();
  const [, view, a, b] = location.hash.split('/');
  try {
    switch (view) {
      case 'list': return await renderList(a, b ? decodeURIComponent(b) : '');
      case 'doc': return await renderDoc(a, b);
      case 'new': return await renderForm(a, b);
      case 'journals': return await renderJournals();
      case 'bank': return await renderBank();
      case 'recon': return await renderRecon();
      case 'cost': return await renderCost();
      case 'stock': return await renderStock();
      case 'evm': return await renderEVM();
      case 'site': return await renderDevices();
      case 'reports': return await renderReports();
      case 'tb': return await renderTB();
      case 'aging': return await renderAging(a === 'ar' ? 'ar' : 'ap');
      case 'ask': return await renderAsk();
      case 'risk': return await renderRisk(a);
      case 'controls': return await renderControls();
      case 'automation': return await renderAutomation();
      case 'settings': return await renderSettings();
      default: return await renderHome();
    }
  } catch (e) {
    if (e instanceof ApiError && e.status === 401 && !/insufficient_user_authentication/.test(e.challenge || '')) return signOut('Your session ended. Sign in again.');
    showError(e);
  }
}

// ---------- sign-in ----------
function renderSignin(msg) {
  $('nav').hidden = true;
  $('who').hidden = true;
  const ta = h('textarea', { name: 'token', autocomplete: 'off', spellcheck: 'false', required: true });
  const form = h('form', { class: 'panel signin', on: { submit: async (ev) => {
    ev.preventDefault();
    S.token = ta.value.trim();
    try {
      S.me = await api('GET', '/v1/identity/me');
      S.can = new Set(S.me.permissions);
      S.ref = S.can.has('p2p.read') ? await api('GET', '/v1/p2p-reference') : { legal_entities: [], projects: [], accounts: [] };
      try { S.company = await api('GET', '/v1/tenant/settings'); } catch { S.company = null; }
      brandCompany();
      $('who-name').textContent = `${S.me.user_id} · ${S.me.roles.join(', ')}`;
      $('who-mfa').hidden = !S.me.mfa;
      $('who').hidden = false;
      buildNav();
      startBell();
      if (location.hash === '' || location.hash === '#/') location.hash = '#/home';
      else route();
      say(`Signed in as ${S.me.user_id}`);
    } catch (e) {
      S.token = null;
      showError(e);
    }
  } } },
  h('h1', { tabindex: '-1' }, 'Sign in'),
  h('p', { class: 'lede' }, 'Paste the access token issued by your organisation’s identity provider. It is kept in this tab’s memory only and is forgotten when you sign out or close the tab.'),
  msg ? h('p', { class: 'notice' }, msg) : null,
  field('Access token', ta),
  h('div', { class: 'actions' }, h('button', { type: 'submit' }, 'Sign in')));
  const v = $('view');
  v.textContent = '';
  v.append(form);
  document.title = 'Sign in — SERK Construction';
  ta.focus();
  stagingSignin(v, ta);
}

// Test environments only: the server offers /staging/* when it runs with
// SERK_ENV=staging and a staging passphrase (refused in production). The
// minted token is an ordinary bearer token; it carries no extra authority.
async function stagingSignin(v, ta) {
  let data;
  try {
    const r = await fetch('/staging/personas');
    if (!r.ok) return;
    data = await r.json();
  } catch { return; }
  const sel = h('select', { name: 'persona', required: true });
  for (const p of data.personas) sel.append(h('option', { value: p.id }, `${p.label} — ${p.roles.join(', ')}`));
  const co = h('select', { name: 'company', required: true });
  for (const c of data.companies || []) co.append(h('option', { value: c.id }, c.name));
  const pw = h('input', { type: 'password', name: 'passphrase', autocomplete: 'off', required: true });
  const panel = h('form', { class: 'panel signin', on: { submit: async (ev) => {
    ev.preventDefault();
    clearError();
    try {
      const r = await fetch('/staging/token', { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ passphrase: pw.value, persona: sel.value, company: co.value || undefined }) });
      const d = await r.json().catch(() => ({}));
      if (!r.ok) throw new ApiError(r.status, (d.error || {}).code || 'error', (d.error || {}).message || r.statusText);
      ta.value = d.token;
      ta.form.requestSubmit();
    } catch (e) { showError(e); }
  } } },
  h('h2', {}, 'Test environment sign-in'),
  h('p', { class: 'notice' }, 'STAGING — synthetic data only. Pick a company and a test persona; each person holds one duty, so switch persona to approve what another prepared. Step-up actions need a sign-in made within the last 10 minutes.'),
  (data.companies || []).length > 1 ? field('Company', co) : null,
  field('Persona', sel),
  field('Staging passphrase', pw),
  h('div', { class: 'actions' }, h('button', { type: 'submit' }, 'Sign in as persona')));
  v.prepend(panel);
}
async function signOut(msg) {
  if (S.token) { try { await api('POST', '/v1/identity/logout'); } catch { /* session may already be gone */ } }
  S.token = null; S.me = null; S.ref = null; S.can = new Set(); S.company = null;
  brandCompany();
  stopBell();
  history.replaceState(null, '', '#/');
  renderSignin(msg || 'You have signed out.');
}

// ---------- home ----------
// Work queues for the signed-in person's permissions (also the bell).
async function workQueues() {
  const qs = QUEUES.filter(([p]) => S.can.has(p));
  const jobs = qs.map(([, type, status]) => api('GET', `/v1/p2p/${type}?status=${status}`).then((r) => r.items.length).catch(() => null));
  if (S.can.has('journal.approve')) jobs.push(Promise.all(['P2P_', 'AR_', 'STK_'].map((p) => api('GET', `/v1/journals?status=DRAFT&source_prefix=${p}`)))
    .then((rs) => rs.reduce((n, r) => n + r.journals.length, 0)).catch(() => null));
  if (S.can.has('journal.post')) jobs.push(api('GET', '/v1/journals?status=APPROVED').then((r) => r.journals.length).catch(() => null));
  const counts = await Promise.all(jobs);
  const all = qs.map(([, type, status, label], i) => ({ label, href: `#/list/${type}/${status}`, n: counts[i] }));
  let k = qs.length;
  if (S.can.has('journal.approve')) all.push({ label: 'Subledger journals to approve', href: '#/journals', n: counts[k++] });
  if (S.can.has('journal.post')) all.push({ label: 'Approved journals to post', href: '#/journals', n: counts[k++] });
  return all;
}
function greeting() {
  const hr = new Date().getHours();
  return hr < 12 ? 'Good morning' : hr < 17 ? 'Good afternoon' : 'Good evening';
}
async function renderHome() {
  const cards = h('div', { class: 'cards' });
  const hero = h('section', { class: 'hero', 'aria-label': 'Summary' });
  page('My work', null, hero, h('h2', { class: 'section' }, 'Waiting for you'), cards,
    h('p', { class: 'foot-note' }, 'Counts include only the projects you can see. Every approval remains a human decision, checked again by the database.'));
  const all = await workQueues();
  const total = all.reduce((n, q) => n + (q.n || 0), 0);
  hero.append(h('div', {}, h('p', { class: 'eyebrow' }, new Date().toLocaleDateString(undefined, { weekday: 'long', day: 'numeric', month: 'long', year: 'numeric' })),
    h('h2', { class: 'hello' }, `${greeting()}, ${S.me.user_id}`), h('p', {}, `Signed in as ${S.me.roles.join(', ').replace(/_/g, ' ')}.`)),
  h('div', { class: 'big' }, String(total), h('small', {}, total === 1 ? 'item waiting' : 'items waiting')));
  if (!all.length) cards.append(h('p', { class: 'empty' }, 'No work queues for your roles.'));
  for (const q of all.sort((a, b) => (b.n || 0) - (a.n || 0))) {
    cards.append(h('a', { class: q.n ? 'card hot' : 'card', href: q.href }, h('div', { class: 'n' }, q.n == null ? '–' : String(q.n)), h('div', { class: 't' }, q.label)));
  }
  setBell(all);
}

// ---------- lists ----------
function table(caption, cols, rows, empty) {
  const t = h('table', {}, h('caption', {}, caption),
    h('thead', {}, h('tr', {}, cols.map((c) => h('th', { scope: 'col', class: c.num ? 'num' : null }, c.label)))),
    h('tbody', {}, rows.length ? rows.map((r) => h('tr', { class: r._class || null }, cols.map((c) => h('td', { class: c.num ? 'num' : null }, c.cell(r))))) :
      h('tr', {}, h('td', { colspan: cols.length, class: 'empty' }, empty || 'Nothing here.'))));
  return h('div', { class: 'tablewrap' }, t);
}

async function renderList(type, status) {
  if (type === 'bank_statement') return renderBank();
  const meta = DOCS[type];
  if (!meta) return renderHome();
  const r = await api('GET', `/v1/p2p/${type}${status ? '?status=' + encodeURIComponent(status) : ''}`);
  const filter = select('status', [{ value: '', label: 'All statuses' }, ...meta.statuses.map((s) => ({ value: s, label: words(s.toLowerCase()) }))]);
  filter.value = status || '';
  filter.addEventListener('change', () => { location.hash = `#/list/${type}${filter.value ? '/' + filter.value : ''}`; });
  const listTitle = `${meta.title}${status ? ' — ' + words(status.toLowerCase()) : ''}`;
  const tools = h('div', { class: 'toolbar' }, field('Status', filter),
    meta.form && S.can.has(meta.create) ? h('a', { class: 'btn', href: `#/new/${meta.form}` }, `New ${meta.one.toLowerCase()}`) : null,
    h('span', { class: 'spacer' }), exportBar(`/v1/p2p/${type}${status ? '?status=' + encodeURIComponent(status) : ''}`, listTitle));
  page(meta.title, null, tools, table(`${meta.title}${status ? ' — ' + words(status.toLowerCase()) : ''} (${r.items.length})`, [
    { label: 'Reference', cell: (d) => {
      const href = meta.link ? meta.link(d) : `#/doc/${type}/${d.id}`;
      return href ? h('a', { href, class: 'ref' }, d.number || d.id.slice(0, 8)) : h('span', { class: 'ref' }, d.number || d.id.slice(0, 8));
    } },
    { label: 'Description', cell: (d) => d.label },
    { label: 'Status', cell: (d) => chip(d.status) },
    { label: 'Amount', num: true, cell: (d) => (d.amount && d.amount !== '0' ? money(d.amount) : '') },
    { label: 'Created by', cell: (d) => d.created_by },
    { label: 'Created', cell: (d) => when(d.created_at) },
  ], r.items, 'No documents match.'));
}

// ---------- document view ----------
// Internal or derived fields that mean nothing to a reader.
const HIDE = new Set(['tenant_id', 'id', 'normalized_number', 'bank_snapshot', 'command_hash', 'source_sha256', 'legal_entity_id', 'match_detail']);
// References to other documents: shown as links, not raw ids.
const REF = { pr_id: 'purchase_requisition', rfq_id: 'rfq', po_id: 'purchase_order', quote_id: 'rfq_quote', awarded_quote_id: 'rfq_quote',
  supplier_id: 'supplier', supplier_bank_id: 'supplier_bank_account', company_bank_id: 'company_bank_account', policy_id: 'p2p_policy',
  customer_id: 'customer', contract_id: 'contract', ipc_id: 'ipc', stock_item_id: 'stock_item', warehouse_id: 'warehouse',
  from_warehouse_id: 'warehouse', to_warehouse_id: 'warehouse' };
// Fields whose target depends on the document carrying them.
const REF_BY_TYPE = { policy_id: { contract: 'contract_policy', ipc: 'contract_policy', customer_invoice: 'contract_policy', customer_credit_note: 'contract_policy', retention_release: 'contract_policy' },
  invoice_id: { customer_credit_note: 'customer_invoice' } };
const refOf = (k, type) => (REF_BY_TYPE[k] && REF_BY_TYPE[k][type]) || REF[k];
// Reading order: what the document is, its state, money, dates, people.
const ORDER = ['number', 'invoice_number', 'statement_no', 'code', 'name', 'description', 'justification', 'status', 'technical_status', 'match_status',
  'currency', 'subtotal', 'tax_amount', 'total', 'amount', 'invoice_date', 'due_date', 'received_on', 'value_date', 'needed_by', 'valid_until', 'due_at'];
const MONEY = /amount|total|price|balance|subtotal|threshold|rate$|gross$|_value$|recovery$|_held$|received$|recovered$|_open$|_released$|_cost$|value_change$|_approved$|^budget$/;
const STAMP = /_at$/;
const rank = (k) => { const i = ORDER.indexOf(k); return i < 0 ? ORDER.length + (/_by$|_at$/.test(k) ? 1 : 0) : i; };
const ordered = (keys) => [...keys].sort((a, b) => rank(a) - rank(b) || a.localeCompare(b));
function fmtValue(k, v) {
  if (typeof v === 'boolean') return v ? 'Yes' : 'No';
  if (STAMP.test(k)) return when(v);
  if (MONEY.test(k) && !/_pct$|_float$/.test(k)) return money(v);
  return String(v);
}
function kv(obj, type) {
  const dl = h('dl', { class: 'kv' });
  for (const k of ordered(Object.keys(obj || {}))) {
    const v = obj[k];
    if (HIDE.has(k) || v == null || typeof v === 'object') continue;
    const ref = refOf(k, type);
    if (ref) {
      if (DOCS[ref]) dl.append(h('dt', {}, words(k.replace(/_id$/, ''))), h('dd', {}, h('a', { href: `#/doc/${ref}/${v}` }, `Open ${DOCS[ref].one.toLowerCase()}`)));
      continue;
    }
    if (/_id$/.test(k)) continue;
    dl.append(h('dt', {}, words(k)), h('dd', {}, fmtValue(k, v)));
  }
  return dl;
}
const LINE_ORDER = ['line_no', 'po_line_no', 'pr_line_no', 'po_line', 'item_no', 'code', 'activity_code', 'name', 'pred_code', 'succ_code', 'link_type', 'lag',
  'duration', 'early_start', 'early_finish', 'late_start', 'late_finish', 'total_float', 'free_float', 'critical', 'budget', 'percent_complete',
  'actual_start', 'actual_finish', 'description', 'unit', 'quantity', 'qty_received', 'received_qty',
  'billed_qty_cumulative', 'est_unit_price', 'unit_price', 'po_price', 'invoice_price', 'rate', 'price_variance_pct', 'within_tolerance', 'est_amount', 'amount', 'note'];
function rowsTable(caption, rows) {
  if (!Array.isArray(rows) || !rows.length) return null;
  const lr = (k) => { const i = LINE_ORDER.indexOf(k); return i < 0 ? LINE_ORDER.length : i; };
  const offsets = new Set(['es', 'ef', 'ls', 'lf']);
  const keys = Object.keys(rows[0]).filter((k) => !HIDE.has(k) && !offsets.has(k) && !/_id$/.test(k) && typeof rows[0][k] !== 'object').sort((a, b) => lr(a) - lr(b));
  return table(caption, keys.map((k) => ({ label: words(k), num: /quantity|qty|price|amount|rate|total|pct|line|budget|duration|float|percent|lag|hours|headcount|version/.test(k),
    cell: (r) => (r[k] == null ? '' : /_pct$/.test(k) ? `${(Number(r[k]) * 100).toFixed(2)}%` : fmtValue(k, r[k])) })), rows);
}

async function renderDoc(type, id) {
  const meta = DOCS[type];
  if (!meta) return renderHome();
  const d = await api('GET', `/v1/p2p/${type}/${id}`);
  const det = d.detail || {};
  const head = det.h || det.q || det;
  const parts = [h('div', { class: 'panel' }, h('p', {}, chip(d.status), ' ', `created by ${d.created_by}`), kv(head, type))];
  const md = head.match_detail;
  if (md && Array.isArray(md.lines)) {
    parts.push(h('div', { class: 'panel' }, h('h2', { class: 'section' }, 'Three-way match'),
      h('p', {}, chip(md.status || head.match_status), ` price tolerance ${(Number(md.price_tolerance_pct) * 100).toFixed(2)}% · VAT ${(Number(md.vat_rate) * 100).toFixed(2)}% · policy version ${md.policy_version}`),
      rowsTable('Invoice against purchase order and confirmed receipts', md.lines)));
  }
  parts.push(rowsTable('Lines', det.lines), rowsTable('Items', det.items), rowsTable('Allocations', det.alloc),
    rowsTable('Activities (critical path computed; the database re-verifies it)', det.activities), rowsTable('Dependencies', det.links),
    rowsTable('Labour (this version)', det.labour), rowsTable('Equipment (this version)', det.equipment));
  if (Array.isArray(det.quotes)) parts.push(rowsTable('Quotes received', det.quotes.map((x) => x.q)));
  if (det.payee) parts.push(h('div', { class: 'panel' }, h('h2', { class: 'section' }, 'Payee (approved bank account)'), kv(det.payee)));
  if (type === 'contract' && d.status === 'ACTIVE') parts.push(await positionPanel(d.id));
  parts.push(actionsPanel(type, d, det), nextSteps(type, d), revealPanel(type, d));
  const docTitle = `${meta.one} ${d.number || head.code || (head.version ? 'v' + head.version : '')}`.trim();
  parts.unshift(h('div', { class: 'toolbar' }, h('span', { class: 'spacer' }), exportBar(`/v1/p2p/${type}/${id}`, docTitle, { entity: () => head.legal_entity_id || '' })));
  page(docTitle, null, ...parts);
}

// Full account numbers are masked everywhere; a holder of bank.details.reveal
// may display one with a stated purpose and a fresh MFA sign-in. The reveal is
// audited on the server; the number is shown once and never stored here.
function revealPanel(type, d) {
  if (!['supplier_bank_account', 'company_bank_account'].includes(type) || !S.can.has('bank.details.reveal')) return null;
  const purpose = input('purpose', { type: 'text', maxlength: '300', required: true });
  const out = h('output', { class: 'reveal', 'aria-live': 'polite' });
  const btn = h('button', { type: 'button', class: 'ghost' }, 'Reveal full account number');
  btn.addEventListener('click', async () => {
    clearError();
    out.textContent = '';
    if (purpose.value.trim().length < 20) { showError(new Error('State the purpose of the reveal (at least 20 characters).')); purpose.focus(); return; }
    btn.disabled = true;
    try {
      const r = await api('POST', `/v1/p2p/${type}/${d.id}/reveal-bank-details`, { purpose: purpose.value.trim() });
      out.textContent = `${r.account_number} (${r.account_name || ''}${r.bank_name ? ', ' + r.bank_name : ''}). This reveal was recorded in the audit log.`;
      purpose.value = '';
    } catch (e) { showError(e); } finally { btn.disabled = false; }
  });
  return h('div', { class: 'panel' }, h('h2', { class: 'section' }, 'Bank details'),
    h('p', { class: 'hint' }, 'Account numbers are masked. Revealing one requires a recent multi-factor sign-in and is audited.'),
    h('div', { class: 'actions' }, field('Purpose of the reveal', purpose), btn), out);
}

async function positionPanel(id) {
  const p = await api('GET', `/v1/contracts/${id}/position`);
  return h('div', { class: 'panel' }, h('h2', { class: 'section' }, 'Commercial position'), kv(p));
}

function nextSteps(type, d) {
  const links = [];
  const add = (perm, href, label) => { if (S.can.has(perm)) links.push(h('a', { class: 'btn', href }, label)); };
  if (type === 'purchase_requisition' && d.status === 'APPROVED') add('rfq.manage', `#/new/rfq/${d.id}`, 'Create RFQ');
  if (type === 'rfq' && d.status === 'ISSUED') add('rfq.manage', `#/new/quote/${d.id}`, 'Record a quote');
  if (type === 'rfq' && d.status === 'AWARDED') add('po.manage', `#/new/po/${d.id}`, 'Create purchase order');
  if (type === 'purchase_order' && d.status === 'APPROVED') {
    add('grn.create', `#/new/grn/${d.id}`, 'Record goods receipt'); add('ap.enter', `#/new/invoice/${d.id}`, 'Enter supplier invoice');
    const assets = new Set(S.ref.accounts.filter((x) => x.kind === 'ASSET').map((x) => x.id));
    if (((d.detail || {}).lines || []).some((l) => !l.stock_item_id && assets.has(l.account_id))) add('po.approve', `#/new/designate/${d.id}`, 'Designate stock items');
  }
  if (type === 'supplier_invoice' && d.status === 'APPROVED') add('payment.prepare', `#/new/payment/${d.id}`, 'Prepare payment');
  if (type === 'customer_invoice' && d.status === 'APPROVED') add('ar.credit.create', `#/new/creditnote/${d.id}`, 'Issue credit note');
  if (type === 'supplier' && d.status === 'ACTIVE') add('supplier.manage', `#/new/supplierbank/${d.id}`, 'Add bank account');
  if (type === 'grn' && d.status === 'CONFIRMED') add('stock.receive', `#/new/putaway/${d.id}`, 'Put away into a warehouse');
  if (type === 'contract' && d.status === 'ACTIVE') { add('measure.create', `#/new/measurement/${d.id}`, 'Record measurement'); add('ipc.prepare', `#/new/ipc/${d.id}`, 'Prepare payment certificate');
    add('ar.retention.create', `#/new/retention/${d.id}`, 'Release retention'); add('contract.manage', `#/new/variation/${d.id}`, 'Record variation'); }
  return links.length ? h('div', { class: 'actions' }, links) : null;
}

function actionsPanel(type, d, det) {
  const meta = DOCS[type];
  const seen = new Set();
  const acts = (meta.actions[d.status] || []).filter(([a, perm]) => S.can.has(perm) && !seen.has(a) && seen.add(a));
  if (!acts.length) return null;
  const box = h('div', { class: 'panel' }, h('h2', { class: 'section' }, 'Actions'));
  for (const [action, , mode] of acts) {
    const extra = [];
    let collect = () => ({});
    if (mode === 'opt' || mode === 'req') {
      const r = input('reason', { type: 'text', maxlength: '500', required: mode === 'req' });
      extra.push(field(mode === 'req' ? `Reason for ${action}` : 'Comment (optional)', r));
      collect = () => (r.value.trim() ? { reason: r.value.trim() } : mode === 'req' ? null : {});
    } else if (mode === 'award') {
      const comp = (det.quotes || []).map((x) => x.q).filter((q) => q.technical_status === 'COMPLIANT');
      const sel = select('quote_id', comp.map((q) => ({ value: q.id, label: `${q.supplier_reference || q.id.slice(0, 8)} — ${money(q.total)}` })));
      const r = input('reason', { type: 'text', maxlength: '500' });
      extra.push(field('Winning quote (technically compliant only)', sel), field('Award reason (required if not the lowest)', r));
      collect = () => (sel.value ? { quote_id: sel.value, reason: r.value.trim() } : null);
    } else if (mode === 'evaluate') {
      const yes = h('input', { type: 'radio', name: 'compliant', value: 'yes', id: nextId('r') });
      const no = h('input', { type: 'radio', name: 'compliant', value: 'no', id: nextId('r') });
      const note = input('note', { type: 'text', maxlength: '500' });
      extra.push(h('fieldset', {}, h('legend', {}, 'Technical evaluation'),
        h('div', { class: 'check' }, yes, h('label', { for: yes.id }, 'Compliant')), h('div', { class: 'check' }, no, h('label', { for: no.id }, 'Not compliant'))),
      field('Evaluation note', note));
      collect = () => (yes.checked || no.checked ? { compliant: yes.checked, note: note.value.trim() } : null);
    } else if (mode === 'certify') {
      const ref = input('certificate_ref', { type: 'text', maxlength: '100', required: true });
      const file = h('input', { type: 'file', name: 'certificate_file', accept: '.pdf,image/*' });
      const sum = h('output', { class: 'hint', 'aria-live': 'polite' });
      let sha = '';
      file.addEventListener('change', async () => {
        sha = '';
        sum.textContent = '';
        if (!file.files.length) return;
        const buf = await crypto.subtle.digest('SHA-256', await file.files[0].arrayBuffer());
        sha = [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
        sum.textContent = `SHA-256 ${sha}`;
      });
      extra.push(field('Client certificate reference', ref), field('Signed certificate file', file, 'Its SHA-256 is recorded with the certification; the file stays with you.'), sum);
      collect = () => (ref.value.trim() && sha ? { certificate_ref: ref.value.trim(), certificate_sha256: sha } : null);
    } else if (mode === 'invoice') {
      const idate = input('invoice_date', { type: 'date', value: today(), required: true });
      const due = input('due_date', { type: 'date', value: plusDays(30), required: true });
      extra.push(field('Invoice date', idate), field('Due date', due));
      collect = () => (idate.value && due.value ? { invoice_date: idate.value, due_date: due.value } : null);
    }
    const btn = h('button', { type: 'button', class: action === 'reject' || action === 'cancel' || action === 'block' ? 'danger' : null }, ACTION_LABEL[action] || action);
    btn.addEventListener('click', async () => {
      clearError();
      const body = collect();
      if (body === null) { showError(new Error('Complete the required fields for this action.')); return; }
      btn.disabled = true;
      try {
        const res = await api('POST', `${meta.base}/${d.id}/${action}`, Object.keys(body).length ? body : undefined);
        if (action === 'invoice' && res && res.id) return created('customer_invoice', res, 'Customer invoice');
        let msg = `${ACTION_LABEL[action] || action}: done.`;
        if (res && res.journal_id) msg += ' A draft journal was created for finance to approve and post.';
        if (res && res.match_status) msg += ` Three-way match: ${res.match_status}.`;
        if (res && res.status) msg += ` Status: ${res.status}.`;
        await renderDoc(type, d.id);
        $('view').insertBefore(h('p', { class: 'notice', role: 'status' }, msg), $('view').children[1]);
        say(msg);
      } catch (e) { btn.disabled = false; showError(e); }
    });
    box.append(h('div', { class: 'actions' }, extra, btn));
  }
  return box;
}

// ---------- forms ----------
const opt = (items, label) => items.map((x) => ({ value: x.id, label: label(x) }));
const entityOpts = () => opt(S.ref.legal_entities, (e) => e.name);
const projectOpts = () => opt(S.ref.projects, (p) => `${p.code} — ${p.name}`);
const accountOpts = (types) => opt(S.ref.accounts.filter((a) => !types || types.includes(a.kind)), (a) => `${a.code} ${a.name}`);
async function docOpts(type, status) {
  const r = await api('GET', `/v1/p2p/${type}?status=${status}`);
  return r.items.map((d) => ({ value: d.id, label: `${d.number || ''} ${d.label}${d.amount && d.amount !== '0' ? ' — ' + money(d.amount) : ''}`.trim() }));
}
const today = () => new Date().toISOString().slice(0, 10);
const plusDays = (n) => new Date(Date.now() + n * 864e5).toISOString().slice(0, 10);

function formPage(title, lede, fields, submitLabel, onSubmit) {
  const btn = h('button', { type: 'submit' }, submitLabel);
  const form = h('form', { class: 'panel', novalidate: true }, fields, h('div', { class: 'actions' }, btn));
  form.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    clearError();
    for (const el of form.querySelectorAll('[required]')) el.setAttribute('aria-invalid', String(!el.value.trim()));
    const bad = form.querySelector('[aria-invalid=true]');
    if (bad) { showError(new Error('Fill in the highlighted fields.')); bad.focus(); return; }
    btn.disabled = true;
    try { await onSubmit(); } catch (e) { showError(e); } finally { btn.disabled = false; }
  });
  page(title, lede, form);
  return form;
}
async function created(type, res, what) {
  say(`${what} created.`);
  location.hash = `#/doc/${type}/${res.id}`;
}

// Editable line grid: cols = [{key,label,make()}].
function lineGrid(legend, cols, initial, allowAdd) {
  const tbody = h('tbody');
  const addRow = (vals = {}) => {
    const tr = h('tr');
    const n = tbody.children.length + 1;
    for (const c of cols) {
      const el = c.make(vals, n);
      el.setAttribute('aria-label', `${c.label}, line ${n}`);
      if (vals[c.key] != null && el.tagName !== 'SPAN') el.value = vals[c.key];
      tr.append(h('td', {}, el));
    }
    if (allowAdd) tr.append(h('td', {}, h('button', { type: 'button', class: 'ghost', 'aria-label': `Remove line ${n}`, on: { click: () => tr.remove() } }, 'Remove')));
    tbody.append(tr);
  };
  (initial.length ? initial : allowAdd ? [{}] : []).forEach(addRow);
  const fs = h('fieldset', {}, h('legend', {}, legend), h('div', { class: 'tablewrap' }, h('table', { class: 'lines' },
    h('thead', {}, h('tr', {}, cols.map((c) => h('th', { scope: 'col' }, c.label)), allowAdd ? h('th', { scope: 'col' }, h('span', { class: 'sr' }, 'Remove')) : null)), tbody)),
  allowAdd ? h('div', { class: 'actions' }, h('button', { type: 'button', class: 'ghost', on: { click: () => addRow() } }, 'Add line')) : null);
  fs.rows = () => [...tbody.children].map((tr) => {
    const o = {};
    cols.forEach((c, i) => { const el = tr.children[i].firstChild; if (el.name) o[c.key] = el.value.trim(); });
    return o;
  });
  return fs;
}
const num = (key, attrs = {}) => () => input(key, { inputmode: 'decimal', autocomplete: 'off', ...attrs });
const txt = (key, attrs = {}) => () => input(key, { type: 'text', ...attrs });
const ro = (key) => (v) => h('span', {}, v[key] == null ? '' : String(v[key]));

async function renderForm(kind, arg) {
  const F = FORMS[kind];
  if (!F) return renderHome();
  return F(arg);
}

const FORMS = {
  async requisition() {
    const proj = select('project_id', projectOpts(), { required: true });
    const just = input('justification', { type: 'text', required: true, maxlength: '500' });
    const need = input('needed_by', { type: 'date', value: plusDays(14) });
    let grid;
    const holder = h('div');
    const load = async () => {
      const cc = proj.value ? (await api('GET', `/v1/projects/${proj.value}/cost-codes`)).cost_codes : [];
      grid = lineGrid('Requested lines', [
        { key: 'cost_code_id', label: 'Cost code', make: () => select('cost_code_id', opt(cc, (c) => `${c.code} ${c.name}`)) },
        { key: 'description', label: 'Description', make: txt('description') },
        { key: 'unit', label: 'Unit', make: txt('unit', { size: '5' }) },
        { key: 'quantity', label: 'Quantity', make: num('quantity') },
        { key: 'est_unit_price', label: 'Estimated unit price', make: num('est_unit_price') },
      ], [], true);
      holder.replaceChildren(grid);
    };
    proj.addEventListener('change', load);
    formPage('New requisition', 'Request materials or services against an approved cost code. Approval checks the project budget.',
      [h('div', { class: 'grid' }, field('Project', proj), field('Justification', just), field('Needed by', need)), holder], 'Create requisition', async () => {
        const lines = grid.rows().map((r, i) => ({ line_no: i + 1, ...r }));
        const res = await api('POST', '/v1/requisitions', { project_id: proj.value, justification: just.value.trim(), needed_by: need.value || undefined, lines });
        created('purchase_requisition', res, 'Requisition');
      });
    await load();
  },

  async boq() {
    const proj = select('project_id', projectOpts(), { required: true });
    const desc = input('description', { type: 'text', required: true });
    let grid;
    const holder = h('div');
    const load = async () => {
      const cc = proj.value ? (await api('GET', `/v1/projects/${proj.value}/cost-codes`)).cost_codes : [];
      grid = lineGrid('BOQ items', [
        { key: 'item_no', label: 'Item no.', make: txt('item_no', { size: '6' }) },
        { key: 'description', label: 'Description', make: txt('description') },
        { key: 'unit', label: 'Unit', make: txt('unit', { size: '5' }) },
        { key: 'quantity', label: 'Quantity', make: num('quantity') },
        { key: 'rate', label: 'Rate', make: num('rate') },
        { key: 'cost_code_id', label: 'Cost code', make: () => select('cost_code_id', opt(cc, (c) => `${c.code} ${c.name}`)) },
      ], [], true);
      holder.replaceChildren(grid);
    };
    proj.addEventListener('change', load);
    formPage('New BOQ version', 'Priced bill of quantities; once approved it is the budget for its cost codes.',
      [h('div', { class: 'grid' }, field('Project', proj), field('Description', desc)), holder], 'Create BOQ', async () => {
        const res = await api('POST', '/v1/boqs', { project_id: proj.value, description: desc.value.trim(), items: grid.rows() });
        created('boq_version', res, 'BOQ');
      });
    await load();
  },

  async rfq(prID) {
    const prs = await docOpts('purchase_requisition', 'APPROVED');
    const pr = select('pr_id', prs, { required: true });
    if (prID) pr.value = prID;
    const due = input('due_at', { type: 'date', value: plusDays(3), required: true });
    const min = input('min_suppliers', { type: 'number', min: '1', max: '10', value: '3' });
    const reason = input('single_source_reason', { type: 'text', maxlength: '500' });
    const sups = (await api('GET', '/v1/p2p/supplier?status=ACTIVE')).items;
    const boxes = sups.map((s) => { const c = h('input', { type: 'checkbox', name: 'supplier', value: s.id, id: nextId('s') }); return h('div', { class: 'check' }, c, h('label', { for: c.id }, `${s.number} — ${s.label}`)); });
    formPage('New RFQ', 'Invite approved suppliers to quote for an approved requisition.', [
      h('div', { class: 'grid' }, field('Requisition', pr), field('Quotes due', due), field('Minimum suppliers', min, 'Fewer than the policy minimum needs a single-source reason.')),
      field('Single-source reason', reason),
      h('fieldset', {}, h('legend', {}, 'Suppliers invited'), boxes.length ? boxes : h('p', { class: 'empty' }, 'No approved suppliers.')),
    ], 'Create RFQ', async () => {
      const ids = boxes.map((b) => b.querySelector('input')).filter((c) => c.checked).map((c) => c.value);
      const res = await api('POST', '/v1/rfqs', { pr_id: pr.value, due_at: new Date(due.value + 'T17:00:00').toISOString(), min_suppliers: Number(min.value),
        single_source_reason: reason.value.trim(), supplier_ids: ids });
      created('rfq', res, 'RFQ');
    });
  },

  async quote(rfqID) {
    const rfqs = await docOpts('rfq', 'ISSUED');
    const rfq = select('rfq_id', rfqs, { required: true });
    if (rfqID) rfq.value = rfqID;
    const holder = h('div');
    let grid, sup, valid, ref;
    const load = async () => {
      holder.textContent = '';
      if (!rfq.value) return;
      const r = (await api('GET', `/v1/p2p/rfq/${rfq.value}`)).detail;
      const prd = (await api('GET', `/v1/p2p/purchase_requisition/${r.h.pr_id}`)).detail;
      const supNames = Object.fromEntries((await api('GET', '/v1/p2p/supplier')).items.map((s) => [s.id, `${s.number} — ${s.label}`]));
      sup = select('supplier_id', (r.suppliers || []).map((id) => ({ value: id, label: supNames[id] || id })), { required: true });
      valid = input('valid_until', { type: 'date', value: plusDays(30), required: true });
      ref = input('supplier_reference', { type: 'text' });
      grid = lineGrid('Quoted prices', [
        { key: 'pr_line_no', label: 'Line', make: (v) => input('pr_line_no', { type: 'hidden', value: String(v.line_no) }) },
        { key: 'description', label: 'Description', make: ro('description') },
        { key: 'quantity', label: 'Quantity', make: ro('quantity') },
        { key: 'unit_price', label: 'Unit price', make: num('unit_price', { required: true }) },
      ], prd.lines.map((l) => ({ ...l, unit_price: '' })), false);
      holder.append(h('div', { class: 'grid' }, field('Supplier', sup), field('Valid until', valid), field('Supplier reference', ref)), grid);
    };
    rfq.addEventListener('change', load);
    formPage('Record quote', 'Enter a supplier’s written quotation against an issued RFQ.', [field('RFQ', rfq), holder], 'Record quote', async () => {
      const lines = grid.rows().map((r) => ({ pr_line_no: Number(r.pr_line_no), unit_price: r.unit_price }));
      const res = await api('POST', `/v1/rfqs/${rfq.value}/quotes`, { supplier_id: sup.value, valid_until: valid.value, supplier_reference: ref.value.trim(), lines });
      say('Quote recorded.');
      location.hash = `#/doc/rfq/${rfq.value}`;
      return res;
    });
    await load();
  },

  async po(rfqID) {
    const rfqs = await docOpts('rfq', 'AWARDED');
    const rfq = select('rfq_id', rfqs, { required: true });
    if (rfqID) rfq.value = rfqID;
    const holder = h('div');
    let grid;
    const load = async () => {
      holder.textContent = '';
      if (!rfq.value) return;
      const r = (await api('GET', `/v1/p2p/rfq/${rfq.value}`)).detail;
      const prd = (await api('GET', `/v1/p2p/purchase_requisition/${r.h.pr_id}`)).detail;
      grid = lineGrid('GL account per line', [
        { key: 'line_no', label: 'Line', make: (v) => input('line_no', { type: 'hidden', value: String(v.line_no) }) },
        { key: 'description', label: 'Description', make: ro('description') },
        { key: 'account', label: 'Expense or asset account', make: () => select('account', accountOpts(['EXPENSE', 'ASSET'])) },
      ], prd.lines, false);
      holder.append(grid);
    };
    rfq.addEventListener('change', load);
    formPage('New purchase order', 'Create the purchase order from the awarded quote. Prices come from the quote and cannot be changed here.', [field('Awarded RFQ', rfq), holder], 'Create purchase order', async () => {
      const accounts = Object.fromEntries(grid.rows().map((r) => [r.line_no, r.account]));
      const res = await api('POST', '/v1/purchase-orders', { rfq_id: rfq.value, accounts });
      created('purchase_order', res, 'Purchase order');
    });
    await load();
  },

  async grn(poID) {
    const pos = await docOpts('purchase_order', 'APPROVED');
    const po = select('po_id', pos, { required: true });
    if (poID) po.value = poID;
    const on = input('received_on', { type: 'date', value: today(), required: true });
    const dn = input('delivery_note', { type: 'text', required: true });
    const holder = h('div');
    let grid;
    const load = async () => {
      holder.textContent = '';
      if (!po.value) return;
      const d = (await api('GET', `/v1/p2p/purchase_order/${po.value}`)).detail;
      grid = lineGrid('Quantities received', [
        { key: 'po_line_no', label: 'Line', make: (v) => input('po_line_no', { type: 'hidden', value: String(v.line_no) }) },
        { key: 'description', label: 'Description', make: ro('description') },
        { key: 'quantity', label: 'Ordered', make: ro('quantity') },
        { key: 'qty_received', label: 'Received now', make: num('qty_received') },
        { key: 'note', label: 'Note', make: txt('note') },
      ], d.lines.map((l) => ({ ...l, qty_received: '' })), false);
      holder.append(grid);
    };
    po.addEventListener('change', load);
    formPage('Record goods receipt', 'Record what physically arrived on site. A site engineer confirms it.', [
      h('div', { class: 'grid' }, field('Purchase order', po), field('Received on', on), field('Delivery note', dn)), holder], 'Record receipt', async () => {
      const lines = grid.rows().filter((r) => r.qty_received).map((r) => ({ po_line_no: Number(r.po_line_no), qty_received: r.qty_received, note: r.note || undefined }));
      const res = await api('POST', '/v1/goods-receipts', { po_id: po.value, received_on: on.value, delivery_note: dn.value.trim(), lines });
      created('grn', res, 'Goods receipt');
    });
    await load();
  },

  async invoice(poID) {
    const pos = await docOpts('purchase_order', 'APPROVED');
    const po = select('po_id', pos, { required: true });
    if (poID) po.value = poID;
    const no = input('invoice_number', { type: 'text', required: true });
    const idate = input('invoice_date', { type: 'date', value: today(), required: true });
    const due = input('due_date', { type: 'date', value: plusDays(30), required: true });
    const sub = input('subtotal', { inputmode: 'decimal', required: true, readonly: true });
    const tax = input('tax_amount', { inputmode: 'decimal', required: true, value: '0' });
    const tot = input('total', { inputmode: 'decimal', required: true, readonly: true });
    const holder = h('div');
    let grid;
    const recalc = () => {
      let s = 0n;
      for (const r of grid ? grid.rows() : []) { const q = dparse(r.quantity), p = dparse(r.unit_price); if (q != null && p != null) s += dmul(q, p); }
      sub.value = dfmt(s);
      const t = dparse(tax.value);
      tot.value = t == null ? '' : dfmt(s + t);
    };
    const load = async () => {
      holder.textContent = '';
      if (!po.value) return;
      const d = (await api('GET', `/v1/p2p/purchase_order/${po.value}`)).detail;
      grid = lineGrid('Invoice lines (as billed)', [
        { key: 'po_line_no', label: 'Line', make: (v) => input('po_line_no', { type: 'hidden', value: String(v.line_no) }) },
        { key: 'description', label: 'Description', make: ro('description') },
        { key: 'quantity', label: 'Quantity billed', make: num('quantity') },
        { key: 'unit_price', label: 'Unit price billed', make: num('unit_price') },
      ], d.lines.map((l) => ({ ...l, quantity: '', unit_price: String(l.unit_price) })), false);
      grid.addEventListener('input', recalc);
      holder.append(grid);
      recalc();
    };
    tax.addEventListener('input', recalc);
    po.addEventListener('change', load);
    formPage('Enter supplier invoice', 'Billed quantities are matched against confirmed receipts and PO prices (three-way match) when you submit.', [
      h('div', { class: 'grid' }, field('Purchase order', po), field('Invoice number', no), field('Invoice date', idate), field('Due date', due)), holder,
      h('div', { class: 'grid' }, field('Subtotal', sub, 'Computed from the lines.'), field('Tax (VAT)', tax, 'As printed on the invoice.'), field('Total', tot))], 'Save invoice', async () => {
      const lines = grid.rows().filter((r) => r.quantity).map((r) => ({ po_line_no: Number(r.po_line_no), quantity: r.quantity, unit_price: r.unit_price }));
      const res = await api('POST', '/v1/invoices', { po_id: po.value, invoice_number: no.value.trim(), invoice_date: idate.value, due_date: due.value,
        subtotal: sub.value, tax_amount: tax.value.trim(), total: tot.value, lines });
      created('supplier_invoice', res, 'Invoice');
    });
    await load();
  },

  async payment(invID) {
    const invs = await docOpts('supplier_invoice', 'APPROVED');
    const inv = select('invoice_id', invs, { required: true });
    if (invID) inv.value = invID;
    const ent = select('legal_entity_id', entityOpts(), { required: true });
    const cbanks = (await api('GET', '/v1/p2p/company_bank_account?status=ACTIVE')).items;
    const cbank = select('company_bank_id', cbanks.map((b) => ({ value: b.id, label: b.label })), { required: true });
    const vdate = input('value_date', { type: 'date', value: today(), required: true });
    const amount = input('amount', { inputmode: 'decimal', required: true });
    const sbank = select('supplier_bank_id', [], { required: true });
    let supplierID = '';
    const load = async () => {
      sbank.textContent = '';
      if (!inv.value) return;
      const d = (await api('GET', `/v1/p2p/supplier_invoice/${inv.value}`)).detail.h;
      supplierID = d.supplier_id;
      amount.value = String(d.total);
      const banks = (await api('GET', '/v1/p2p/supplier_bank_account?status=APPROVED')).items;
      for (const b of banks) {
        const bd = (await api('GET', `/v1/p2p/supplier_bank_account/${b.id}`)).detail;
        if (bd.supplier_id === supplierID) sbank.append(h('option', { value: b.id }, b.label));
      }
    };
    inv.addEventListener('change', load);
    formPage('Prepare payment', 'Pays an approved invoice to the supplier’s approved bank account. Approval and release are done by other people.', [
      h('div', { class: 'grid' }, field('Invoice', inv), field('Amount to pay', amount), field('Legal entity', ent), field('Pay from', cbank),
        field('Pay to (approved account)', sbank), field('Value date', vdate))], 'Create payment instruction', async () => {
      const res = await api('POST', '/v1/payments', { legal_entity_id: ent.value, supplier_id: supplierID, supplier_bank_id: sbank.value, company_bank_id: cbank.value,
        value_date: vdate.value, allocations: [{ invoice_id: inv.value, amount: amount.value.trim() }] });
      created('payment_instruction', res, 'Payment instruction');
    });
    await load();
  },

  async supplier() {
    const ent = select('legal_entity_id', entityOpts(), { required: true });
    const code = input('code', { type: 'text', required: true });
    const name = input('name', { type: 'text', required: true });
    const tin = input('tax_id', { type: 'text', required: true });
    formPage('New supplier', 'A procurement manager approves the supplier before it can be invited or paid.', [
      h('div', { class: 'grid' }, field('Legal entity', ent), field('Supplier code', code), field('Legal name', name), field('Tax ID (TIN)', tin))], 'Create supplier', async () => {
      const res = await api('POST', '/v1/suppliers', { legal_entity_id: ent.value, code: code.value.trim(), name: name.value.trim(), tax_id: tin.value.trim() });
      created('supplier', res, 'Supplier');
    });
  },

  async supplierbank(supID) {
    const sups = await docOpts('supplier', 'ACTIVE');
    const sup = select('supplier_id', sups, { required: true });
    if (supID) sup.value = supID;
    const bank = input('bank_name', { type: 'text', required: true });
    const an = input('account_name', { type: 'text', required: true });
    const no = input('account_number', { type: 'text', required: true, autocomplete: 'off' });
    const cur = input('currency', { type: 'text', value: 'ETB', maxlength: '3', required: true });
    formPage('New supplier bank account', 'Finance verifies and approves bank details before any payment can use them.', [
      h('div', { class: 'grid' }, field('Supplier', sup), field('Bank', bank), field('Account name', an), field('Account number', no), field('Currency', cur))], 'Add bank account', async () => {
      const res = await api('POST', `/v1/suppliers/${sup.value}/bank-accounts`, { bank_name: bank.value.trim(), account_name: an.value.trim(), account_number: no.value.trim(), currency: cur.value.trim() });
      created('supplier_bank_account', res, 'Bank account');
    });
  },

  async companybank() {
    const ent = select('legal_entity_id', entityOpts(), { required: true });
    const name = input('name', { type: 'text', required: true });
    const no = input('account_number', { type: 'text', required: true, autocomplete: 'off' });
    const cur = input('currency', { type: 'text', value: 'ETB', maxlength: '3', required: true });
    const gl = select('gl_account_id', accountOpts(['ASSET']), { required: true });
    const clr = select('clearing_account_id', accountOpts(['ASSET']), { required: true });
    formPage('New company bank account', 'The CFO approves company bank accounts.', [
      h('div', { class: 'grid' }, field('Legal entity', ent), field('Name', name), field('Account number', no), field('Currency', cur),
        field('Bank GL account', gl), field('Payments-in-transit account', clr))], 'Register account', async () => {
      const res = await api('POST', '/v1/company-bank-accounts', { legal_entity_id: ent.value, name: name.value.trim(), account_number: no.value.trim(),
        currency: cur.value.trim(), gl_account_id: gl.value, clearing_account_id: clr.value });
      created('company_bank_account', res, 'Company bank account');
    });
  },

  async customer() {
    const ent = select('legal_entity_id', entityOpts(), { required: true });
    const code = input('code', { type: 'text', required: true });
    const name = input('name', { type: 'text', required: true });
    const tin = input('tax_id', { type: 'text' });
    formPage('New customer', 'A finance manager approves the customer before contracts can be made with it.', [
      h('div', { class: 'grid' }, field('Legal entity', ent), field('Customer code', code), field('Legal name', name), field('Tax ID (TIN)', tin))], 'Create customer', async () => {
      const res = await api('POST', '/v1/customers', { legal_entity_id: ent.value, code: code.value.trim(), name: name.value.trim(), tax_id: tin.value.trim() });
      created('customer', res, 'Customer');
    });
  },

  async contractpolicy() {
    const ent = select('legal_entity_id', entityOpts(), { required: true });
    const vat = input('vat_rate', { inputmode: 'decimal', value: '0.15', required: true });
    const base = select('vat_base', [{ value: 'GROSS_LESS_ADVANCE', label: 'Gross less advance recovery' }, { value: 'GROSS', label: 'Gross' }]);
    const acc = (n, types) => select(n, accountOpts(types), { required: true });
    const ar = acc('ar_account_id', ['ASSET']), ret = acc('retention_account_id', ['ASSET']), adv = acc('advance_account_id', ['LIABILITY']);
    const rev = acc('revenue_account_id', ['REVENUE']), vout = acc('vat_output_account_id', ['LIABILITY']);
    formPage('Propose contract policy', 'VAT and receivable posting accounts for client contracts. Takes effect only after the CFO approves it. Rates are tenant configuration, not tax advice.', [
      h('div', { class: 'grid' }, field('Legal entity', ent), field('VAT rate (fraction)', vat, '0.15 = 15%'), field('VAT base', base),
        field('Accounts receivable', ar), field('Retention receivable', ret), field('Advances from customers', adv), field('Contract revenue', rev), field('VAT output', vout))],
    'Propose policy', async () => {
      const res = await api('POST', '/v1/contract-policies', { legal_entity_id: ent.value, vat_rate: vat.value.trim(), vat_base: base.value, ar_account_id: ar.value,
        retention_account_id: ret.value, advance_account_id: adv.value, revenue_account_id: rev.value, vat_output_account_id: vout.value });
      created('contract_policy', res, 'Contract policy');
    });
  },

  async contract() {
    const proj = select('project_id', projectOpts(), { required: true });
    const cust = select('customer_id', await docOpts('customer', 'ACTIVE'), { required: true });
    const title = input('title', { type: 'text', required: true, maxlength: '200' });
    const ref = input('client_reference', { type: 'text', required: true, maxlength: '100' });
    const signed = input('signed_on', { type: 'date', value: today(), required: true });
    const ret = input('retention_pct', { inputmode: 'decimal', value: '0.05', required: true });
    const adv = input('advance_amount', { inputmode: 'decimal', value: '0', required: true });
    const rec = input('advance_recovery_pct', { inputmode: 'decimal', value: '0', required: true });
    const grid = lineGrid('Contract lines (bill of quantities as signed)', [
      { key: 'description', label: 'Description', make: txt('description') },
      { key: 'unit', label: 'Unit', make: txt('unit', { size: '5' }) },
      { key: 'quantity', label: 'Quantity', make: num('quantity') },
      { key: 'rate', label: 'Rate', make: num('rate') },
    ], [], true);
    formPage('New client contract', 'The contract value is computed from the lines. The CFO activates the contract with a recent multi-factor sign-in.', [
      h('div', { class: 'grid' }, field('Project', proj), field('Customer', cust), field('Title', title), field('Client reference', ref), field('Signed on', signed),
        field('Retention (fraction)', ret, '0.05 = 5%'), field('Advance amount', adv), field('Advance recovery (fraction of each certificate)', rec)), grid], 'Create contract', async () => {
      const lines = grid.rows().map((r, i) => ({ line_no: i + 1, ...r }));
      const res = await api('POST', '/v1/contracts', { project_id: proj.value, customer_id: cust.value, title: title.value.trim(), client_reference: ref.value.trim(),
        signed_on: signed.value, retention_pct: ret.value.trim(), advance_amount: adv.value.trim(), advance_recovery_pct: rec.value.trim(), lines });
      created('contract', res, 'Contract');
    });
  },

  async measurement(contractID) {
    const ctr = select('contract_id', await docOpts('contract', 'ACTIVE'), { required: true });
    if (contractID) ctr.value = contractID;
    const period = input('period_end', { type: 'date', value: today(), required: true });
    let grid;
    const holder = h('div');
    const load = async () => {
      const lines = ctr.value ? ((await api('GET', `/v1/p2p/contract/${ctr.value}`)).detail.lines || []) : [];
      grid = lineGrid('Quantities measured this period (leave blank for no work)', [
        { key: 'contract_line_no', label: 'Line', make: (v) => input('contract_line_no', { type: 'hidden', value: String(v.line_no) }) },
        { key: 'description', label: 'Description', make: ro('description') },
        { key: 'unit', label: 'Unit', make: ro('unit') },
        { key: 'contract_qty', label: 'Signed quantity (variations add to it)', make: (v) => h('span', {}, String(v.contract_qty)) },
        { key: 'quantity', label: 'Measured quantity', make: num('quantity') },
      ], lines.map((l) => ({ line_no: l.line_no, description: l.description, unit: l.unit, contract_qty: l.quantity })), false);
      holder.replaceChildren(grid);
    };
    ctr.addEventListener('change', load);
    formPage('Record measurement', 'Quantities of work done in the period. A site engineer verifies them; the database refuses quantities beyond the contract.', [
      h('div', { class: 'grid' }, field('Contract', ctr), field('Period ending', period)), holder], 'Create measurement', async () => {
      const lines = grid.rows().filter((r) => r.quantity).map((r) => ({ contract_line_no: Number(r.contract_line_no), quantity: r.quantity }));
      if (!lines.length) throw new Error('Enter at least one measured quantity.');
      const res = await api('POST', `/v1/contracts/${ctr.value}/measurements`, { period_end: period.value, lines });
      created('measurement', res, 'Measurement');
    });
    await load();
  },

  async variation(contractID) {
    const ctr = select('contract_id', await docOpts('contract', 'ACTIVE'), { required: true });
    if (contractID) ctr.value = contractID;
    const title = input('title', { type: 'text', maxlength: '300', required: true });
    const reason = input('reason', { type: 'text', maxlength: '2000', required: true });
    const ref = input('client_instruction_ref', { type: 'text', maxlength: '100', required: true });
    const file = h('input', { type: 'file', name: 'instruction_file', accept: '.pdf,image/*' });
    const sum = h('output', { class: 'hint', 'aria-live': 'polite' });
    let sha = '';
    file.addEventListener('change', async () => {
      sha = '';
      sum.textContent = '';
      if (!file.files.length) return;
      const buf = await crypto.subtle.digest('SHA-256', await file.files[0].arrayBuffer());
      sha = [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
      sum.textContent = `SHA-256 ${sha}`;
    });
    let changes;
    const holder = h('div');
    const load = async () => {
      const lines = ctr.value ? ((await api('GET', `/v1/p2p/contract/${ctr.value}`)).detail.lines || []) : [];
      changes = lineGrid('Quantity changes to existing lines (negative for an omission; leave blank for none)', [
        { key: 'line_no', label: 'Line', make: (v) => input('line_no', { type: 'hidden', value: String(v.line_no) }) },
        { key: 'description', label: 'Description', make: ro('description') },
        { key: 'rate', label: 'Contract rate', make: (v) => h('span', {}, money(v.rate)) },
        { key: 'qty_delta', label: 'Quantity change', make: num('qty_delta') },
      ], lines.map((l) => ({ line_no: l.line_no, description: l.description, rate: l.rate })), false);
      holder.replaceChildren(changes);
    };
    ctr.addEventListener('change', load);
    const added = lineGrid('New lines', [
      { key: 'line_no', label: 'Line number', make: num('line_no') },
      { key: 'description', label: 'Description', make: txt('description') },
      { key: 'unit', label: 'Unit', make: txt('unit', { size: '6' }) },
      { key: 'qty_delta', label: 'Quantity', make: num('qty_delta') },
      { key: 'rate', label: 'Rate', make: num('rate') },
    ], [], true);
    formPage('Record variation', 'A change to the contract on the client\'s written instruction. Quantity changes are priced at the contract rate; new lines carry their own rate. The CFO approves with a fresh multi-factor sign-in.', [
      h('div', { class: 'grid' }, field('Contract', ctr), field('Title', title), field('Client instruction reference', ref)), field('Reason', reason),
      field('Signed client instruction', file, 'Its SHA-256 is recorded with the variation; the file stays with you.'), sum, holder, added], 'Create variation', async () => {
      if (!sha) throw new Error('Attach the signed client instruction so its SHA-256 can be recorded.');
      const lines = [...changes.rows().filter((r) => r.qty_delta).map((r) => ({ line_no: Number(r.line_no), kind: 'CHANGE', qty_delta: r.qty_delta })),
        ...added.rows().filter((r) => r.line_no && r.qty_delta).map((r) => ({ line_no: Number(r.line_no), kind: 'NEW', description: r.description, unit: r.unit,
          qty_delta: r.qty_delta, rate: r.rate || '0' }))];
      if (!lines.length) throw new Error('Enter at least one quantity change or new line.');
      const res = await api('POST', `/v1/contracts/${ctr.value}/variations`, { title: title.value.trim(), reason: reason.value.trim(),
        client_instruction_ref: ref.value.trim(), client_instruction_sha256: sha, lines });
      created('contract_variation', res, 'Variation');
    });
    await load();
  },

  async ipc(contractID) {
    const ctr = select('contract_id', await docOpts('contract', 'ACTIVE'), { required: true });
    if (contractID) ctr.value = contractID;
    const period = input('period_end', { type: 'date', value: today(), required: true });
    formPage('Prepare payment certificate', 'Every amount — gross, retention, advance recovery, VAT and amount due — is computed from verified measurements and the contract.', [
      h('div', { class: 'grid' }, field('Contract', ctr), field('Period ending', period))], 'Prepare certificate', async () => {
      const res = await api('POST', `/v1/contracts/${ctr.value}/ipcs`, { period_end: period.value });
      created('ipc', res, 'Payment certificate');
    });
  },

  async receipt(lineID) {
    const lines = (await api('GET', '/v1/p2p/money_in?status=UNAPPLIED')).items;
    const line = select('statement_line_id', lines.map((l) => ({ value: l.id, label: `${l.number} ${l.label} — ${money(l.amount)}` })), { required: true });
    if (lineID) line.value = lineID;
    const targets = [...(await docOpts('customer_invoice', 'APPROVED')).map((o) => ({ value: 'inv:' + o.value, label: 'Invoice ' + o.label })),
      ...(await docOpts('retention_release', 'APPROVED')).map((o) => ({ value: 'rel:' + o.value, label: 'Retention release ' + o.label })),
      ...(await docOpts('contract', 'ACTIVE')).map((o) => ({ value: 'adv:' + o.value, label: 'Advance on ' + o.label }))];
    const amountOf = () => (lines.find((l) => l.id === line.value) || {}).amount || '';
    const grid = lineGrid('Apply the money to', [
      { key: 'target', label: 'Invoice or contract advance', make: () => select('target', targets) },
      { key: 'amount', label: 'Amount', make: num('amount') },
    ], [{ amount: amountOf() }], true);
    formPage('Record receipt', 'Apply money received on the bank statement. The whole amount must be applied; an AR supervisor independent of the statement import confirms it.', [
      h('div', { class: 'grid' }, field('Money received', line)), grid], 'Record receipt', async () => {
      const key = { inv: 'invoice_id', rel: 'retention_release_id', adv: 'contract_id' };
      const allocations = grid.rows().filter((r) => r.target && r.amount).map((r) => ({ [key[r.target.slice(0, 3)]]: r.target.slice(4), amount: r.amount }));
      const res = await api('POST', '/v1/receipts', { statement_line_id: line.value, allocations });
      created('customer_receipt', res, 'Receipt');
    });
  },

  async creditnote(invoiceID) {
    const inv = select('invoice_id', await docOpts('customer_invoice', 'APPROVED'), { required: true });
    if (invoiceID) inv.value = invoiceID;
    const kind = select('kind', [{ value: 'COMMERCIAL', label: 'Commercial settlement (amount)' }, { value: 'QUANTITY_CORRECTION', label: 'Quantity correction (contract line and quantity)' }]);
    const amount = input('net_amount', { inputmode: 'decimal', autocomplete: 'off' });
    const line = input('correction_line_no', { inputmode: 'numeric', autocomplete: 'off' });
    const qty = input('correction_qty', { inputmode: 'decimal', autocomplete: 'off' });
    const date = input('credit_date', { type: 'date', value: today(), required: true });
    const reason = input('reason', { type: 'text', maxlength: '500', required: true });
    formPage('Issue credit note', 'Reduces what an approved invoice bills. A commercial settlement is an amount before VAT; a quantity correction names the contract line and the over-measured quantity, and is valued at the line rate (it also reduces the verified quantity, so the work is never deducted twice). A commercial manager approves it with a fresh multi-factor sign-in.', [
      h('div', { class: 'grid' }, field('Customer invoice', inv), field('Kind', kind), field('Credit date', date)),
      h('div', { class: 'grid' }, field('Amount credited (before VAT)', amount), field('Contract line', line), field('Quantity over-measured', qty)),
      field('Reason', reason)], 'Issue credit note', async () => {
      const body = { credit_date: date.value, reason: reason.value.trim() };
      if (kind.value === 'QUANTITY_CORRECTION') { body.correction_line_no = Number(line.value); body.correction_qty = qty.value.trim(); } else { body.net_amount = amount.value.trim(); }
      const res = await api('POST', `/v1/customer-invoices/${inv.value}/credit-notes`, body);
      created('customer_credit_note', res, 'Credit note');
    });
  },

  async retention(contractID) {
    const ctr = select('contract_id', await docOpts('contract', 'ACTIVE'), { required: true });
    if (contractID) ctr.value = contractID;
    const amount = input('amount', { inputmode: 'decimal', autocomplete: 'off', required: true });
    const date = input('release_date', { type: 'date', value: today(), required: true });
    const milestone = select('milestone', [{ value: 'TAKING_OVER', label: 'Taking over (practical completion)' },
      { value: 'DEFECTS_LIABILITY_END', label: 'End of defects liability period' }, { value: 'NEGOTIATED', label: 'Negotiated release' }]);
    const ref = input('certificate_ref', { type: 'text', maxlength: '100', required: true });
    const file = h('input', { type: 'file', name: 'certificate_file', accept: '.pdf,image/*' });
    const sum = h('output', { class: 'hint', 'aria-live': 'polite' });
    let sha = '';
    file.addEventListener('change', async () => {
      sha = '';
      sum.textContent = '';
      if (!file.files.length) return;
      const buf = await crypto.subtle.digest('SHA-256', await file.files[0].arrayBuffer());
      sha = [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
      sum.textContent = `SHA-256 ${sha}`;
    });
    formPage('Release retention', 'Records the client\'s retention release certificate. The amount becomes receivable once a commercial manager approves it with a fresh multi-factor sign-in; it cannot exceed the retention still held.', [
      h('div', { class: 'grid' }, field('Contract', ctr), field('Amount released', amount), field('Release date', date), field('Milestone', milestone),
        field('Client certificate reference', ref)),
      field('Signed release certificate', file, 'Its SHA-256 is recorded with the release; the file stays with you.'), sum], 'Record release', async () => {
      if (!sha) throw new Error('Attach the signed release certificate so its SHA-256 can be recorded.');
      const res = await api('POST', `/v1/contracts/${ctr.value}/retention-releases`, { amount: amount.value.trim(), release_date: date.value,
        milestone: milestone.value, certificate_ref: ref.value.trim(), certificate_sha256: sha });
      created('retention_release', res, 'Retention release');
    });
  },

  async schedule() {
    const proj = select('project_id', projectOpts(), { required: true });
    const desc = input('description', { type: 'text', maxlength: '500', required: true });
    const start = input('start_date', { type: 'date', value: today(), required: true });
    const finish = input('required_finish', { type: 'date' });
    const holidays = input('holidays', { type: 'text', placeholder: '2026-12-25, 2027-01-07' });
    const days = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'].map((name, i) => {
      const cb = h('input', { type: 'checkbox', name: 'weekday', value: String(i), id: nextId('wd') });
      cb.checked = i >= 1 && i <= 6;
      return h('div', { class: 'check' }, cb, h('label', { for: cb.id }, name));
    });
    let acts;
    const actHolder = h('div');
    const loadActs = async () => {
      const ccs = proj.value ? (await api('GET', `/v1/projects/${proj.value}/cost-codes`)).cost_codes : [];
      const ccOpts = [{ value: '', label: '(none)' }, ...opt(ccs, (c) => `${c.code} ${c.name}`)];
      acts = lineGrid('Activities', [
        { key: 'code', label: 'Code', make: txt('code', { size: '8' }) },
        { key: 'name', label: 'Name', make: txt('name') },
        { key: 'duration', label: 'Duration (working days)', make: num('duration') },
        { key: 'cost_code_id', label: 'Cost code', make: () => select('cost_code_id', ccOpts) },
        { key: 'budget', label: 'Budget', make: num('budget') },
      ], [], true);
      actHolder.replaceChildren(acts);
    };
    proj.addEventListener('change', () => loadActs().catch(showError));
    await loadActs();
    const links = lineGrid('Dependencies', [
      { key: 'pred', label: 'Predecessor', make: txt('pred', { size: '8' }) },
      { key: 'succ', label: 'Successor', make: txt('succ', { size: '8' }) },
      { key: 'type', label: 'Type', make: () => select('type', ['FS', 'SS', 'FF', 'SF'].map((x) => ({ value: x, label: x }))) },
      { key: 'lag', label: 'Lag (days)', make: num('lag') },
    ], [], true);
    formPage('New schedule', 'Activities and dependencies on a working-day calendar. The critical path is computed when you save and verified again by the database when you submit; a project manager approves it as the baseline.', [
      h('div', { class: 'grid' }, field('Project', proj), field('Description', desc), field('Start date', start), field('Required finish (optional)', finish),
        field('Holidays (dates, comma-separated)', holidays)),
      h('fieldset', {}, h('legend', {}, 'Working days'), days), actHolder, links], 'Compute and save', async () => {
      const weekdays = [...document.querySelectorAll('input[name=weekday]')].filter((c) => c.checked).map((c) => Number(c.value));
      const hol = holidays.value.split(',').map((x) => x.trim()).filter(Boolean);
      const activities = acts.rows().filter((r) => r.code).map((r) => ({ code: r.code, name: r.name, duration: Number(r.duration || 0),
        budget: r.budget || '0', cost_code_id: r.cost_code_id || undefined }));
      const deps = links.rows().filter((r) => r.pred && r.succ).map((r) => ({ pred: r.pred, succ: r.succ, type: r.type, lag: Number(r.lag || 0) }));
      const res = await api('POST', `/v1/projects/${proj.value}/schedules`, { description: desc.value.trim(), start_date: start.value, working_weekdays: weekdays,
        holidays: hol, required_finish: finish.value || undefined, activities, links: deps });
      created('schedule_version', res, 'Schedule');
    });
  },

  async diary() {
    const proj = select('project_id', projectOpts(), { required: true });
    const at = input('diary_date', { type: 'date', value: today(), required: true });
    const weather = input('weather', { type: 'text', required: true, maxlength: '200' });
    const notes = h('textarea', { name: 'notes', maxlength: '8000', rows: '4' });
    const labour = lineGrid('Labour (trade, headcount, person-hours)', [
      { key: 'trade', label: 'Trade', make: txt('trade', { maxlength: '100' }) },
      { key: 'headcount', label: 'Headcount', make: num('headcount', { inputmode: 'numeric' }) },
      { key: 'hours', label: 'Person-hours', make: num('hours') },
    ], [], true);
    const equipment = lineGrid('Equipment (hours worked and idle)', [
      { key: 'description', label: 'Equipment', make: txt('description', { maxlength: '200' }) },
      { key: 'hours', label: 'Hours worked', make: num('hours') },
      { key: 'idle_hours', label: 'Hours idle', make: num('idle_hours') },
    ], [], true);
    formPage('Record a site diary', 'One diary per project and day. A project manager approves it after you submit it. Field devices record diaries offline and synchronise them.', [
      h('div', { class: 'grid' }, field('Project', proj), field('Date', at), field('Weather', weather)), field('Notes', notes), labour, equipment], 'Save diary', async () => {
      const lab = labour.rows().filter((r) => r.trade).map((r) => ({ trade: r.trade, headcount: Number(r.headcount), hours: r.hours }));
      const eq = equipment.rows().filter((r) => r.description).map((r) => ({ description: r.description, hours: r.hours || '0', idle_hours: r.idle_hours || '0' }));
      const res = await api('POST', '/v1/site/diaries', { client_ref: crypto.randomUUID(), project_id: proj.value, diary_date: at.value, weather: weather.value.trim(),
        notes: notes.value, base_version: 0, labour: lab, equipment: eq });
      created('site_diary', res, 'Site diary');
    });
  },

  async progress() {
    const proj = select('project_id', projectOpts(), { required: true });
    const at = input('status_date', { type: 'date', value: today(), required: true });
    let grid;
    let seq = 0;
    const holder = h('div');
    const load = async () => {
      const mine = ++seq;
      grid = null;
      holder.textContent = '';
      if (!proj.value) return;
      const base = (await api('GET', `/v1/p2p/schedule_version?status=BASELINE`)).items.find((x) => x.project_id === proj.value);
      if (mine !== seq) return;
      if (!base) { holder.append(h('p', { class: 'empty' }, 'The project has no baseline schedule.')); return; }
      const acts = (await api('GET', `/v1/p2p/schedule_version/${base.id}`)).detail.activities || [];
      if (mine !== seq) return;
      grid = lineGrid('Progress by activity (leave percent blank to skip)', [
        { key: 'activity_code', label: 'Activity', make: (v) => input('activity_code', { type: 'hidden', value: v.code }) },
        { key: 'name', label: 'Name', make: ro('name') },
        { key: 'percent_complete', label: 'Percent complete', make: num('percent_complete') },
        { key: 'actual_start', label: 'Actual start', make: () => input('actual_start', { type: 'date' }) },
        { key: 'actual_finish', label: 'Actual finish', make: () => input('actual_finish', { type: 'date' }) },
      ], acts.map((a) => ({ code: a.code, name: `${a.code} ${a.name}` })), false);
      holder.replaceChildren(grid);
    };
    proj.addEventListener('change', () => load().catch(showError));
    formPage('Report progress', 'Percent complete and actual dates at a status date, against the approved baseline. A project manager approves the report; earned value uses it.', [
      h('div', { class: 'grid' }, field('Project', proj), field('Status date', at)), holder], 'Record progress', async () => {
      const lines = (grid ? grid.rows() : []).filter((r) => r.percent_complete !== '').map((r) => ({ activity_code: r.activity_code, percent_complete: r.percent_complete,
        actual_start: r.actual_start || undefined, actual_finish: r.actual_finish || undefined }));
      if (!lines.length) throw new Error('Enter progress for at least one activity.');
      const res = await api('POST', `/v1/projects/${proj.value}/progress`, { status_date: at.value, lines });
      created('schedule_progress', res, 'Progress report');
    });
    await load();
  },

  async designate(poID) {
    const po = (await api('GET', `/v1/p2p/purchase_order/${poID}`)).detail;
    const assets = new Set(S.ref.accounts.filter((x) => x.kind === 'ASSET').map((x) => x.id));
    const open = (po.lines || []).filter((l) => !l.stock_item_id && assets.has(l.account_id));
    const line = select('line_no', open.map((l) => ({ value: String(l.line_no), label: `${l.line_no} — ${l.description} (${l.unit})` })), { required: true });
    const item = select('stock_item_id', await docOpts('stock_item', 'ACTIVE'), { required: true });
    formPage('Designate stock items', 'Names the stock item an inventory line of this purchase order delivers. It is set once, before anything is put away; the storekeeper then puts away only that item.', [
      h('div', { class: 'grid' }, field('Purchase order line', line), field('Stock item', item))], 'Designate', async () => {
      await api('POST', `/v1/purchase-orders/${poID}/lines/${line.value}/stock-item`, { stock_item_id: item.value });
      say('Stock item designated.');
      location.hash = `#/doc/purchase_order/${poID}`;
    });
  },

  async stockitem() {
    const ent = select('legal_entity_id', entityOpts(), { required: true });
    const code = input('code', { type: 'text', required: true });
    const name = input('name', { type: 'text', required: true });
    const unit = input('unit', { type: 'text', required: true, size: '6' });
    const method = select('valuation_method', [{ value: 'FIFO', label: 'FIFO (first in, first out)' }, { value: 'WAC', label: 'Weighted average cost' }]);
    const acct = select('inventory_account_id', accountOpts(['ASSET']), { required: true });
    formPage('New stock item', 'Finance approves the item before stock can be received or issued. The unit must match the purchase order line.', [
      h('div', { class: 'grid' }, field('Legal entity', ent), field('Item code', code), field('Name', name), field('Unit', unit), field('Valuation', method),
        field('Inventory account', acct))], 'Create stock item', async () => {
      const res = await api('POST', '/v1/stock-items', { legal_entity_id: ent.value, code: code.value.trim(), name: name.value.trim(), unit: unit.value.trim(),
        valuation_method: method.value, inventory_account_id: acct.value });
      created('stock_item', res, 'Stock item');
    });
  },

  async warehouse() {
    const ent = select('legal_entity_id', entityOpts(), { required: true });
    const proj = select('project_id', [{ value: '', label: 'Central (no project)' }, ...projectOpts()]);
    const code = input('code', { type: 'text', required: true });
    const name = input('name', { type: 'text', required: true });
    formPage('New warehouse', 'A project store holds stock for one project; a central warehouse serves the whole entity.', [
      h('div', { class: 'grid' }, field('Legal entity', ent), field('Project', proj), field('Code', code), field('Name', name))], 'Create warehouse', async () => {
      const res = await api('POST', '/v1/warehouses', { legal_entity_id: ent.value, project_id: proj.value || undefined, code: code.value.trim(), name: name.value.trim() });
      created('warehouse', res, 'Warehouse');
    });
  },

  async putaway(grnID) {
    const grns = await docOpts('grn', 'CONFIRMED');
    const grn = select('grn_id', grns, { required: true });
    if (grnID) grn.value = grnID;
    const items = select('stock_item_id', await docOpts('stock_item', 'ACTIVE'), { required: true });
    const wh = select('warehouse_id', await docOpts('warehouse', 'ACTIVE'), { required: true });
    const line = input('po_line_no', { type: 'number', min: '1', value: '1', required: true });
    const qty = input('quantity', { inputmode: 'decimal', required: true });
    formPage('Put away into a warehouse', 'Moves received goods into stock at the purchase order price. The goods receipt line must have been posted to the item\'s inventory account.', [
      h('div', { class: 'grid' }, field('Goods receipt', grn), field('Purchase order line', line), field('Stock item', items), field('Warehouse', wh), field('Quantity', qty))],
    'Put away', async () => {
      await api('POST', `/v1/goods-receipts/${grn.value}/put-away`, { po_line_no: Number(line.value), stock_item_id: items.value, warehouse_id: wh.value, quantity: qty.value.trim() });
      say('Put away.');
      location.hash = '#/stock';
    });
  },

  async stocktransfer() {
    const whs = await docOpts('warehouse', 'ACTIVE');
    const from = select('from_warehouse_id', whs, { required: true });
    const to = select('to_warehouse_id', whs, { required: true });
    const item = select('stock_item_id', await docOpts('stock_item', 'ACTIVE'), { required: true });
    const qty = input('quantity', { inputmode: 'decimal', required: true });
    const date = input('transfer_date', { type: 'date', value: today(), required: true });
    const note = input('note', { type: 'text', maxlength: '500' });
    formPage('Transfer stock', 'Moves stock between two warehouses at cost; nothing is expensed and no journal is needed. An inventory controller approves it.', [
      h('div', { class: 'grid' }, field('From warehouse', from), field('To warehouse', to), field('Stock item', item), field('Quantity', qty), field('Transfer date', date)),
      field('Note', note)], 'Request transfer', async () => {
      if (from.value === to.value) throw new Error('Choose two different warehouses.');
      const res = await api('POST', '/v1/stock-transfers', { stock_item_id: item.value, from_warehouse_id: from.value, to_warehouse_id: to.value,
        quantity: qty.value.trim(), transfer_date: date.value, note: note.value.trim() || undefined });
      created('stock_transfer', res, 'Stock transfer');
    });
  },

  async stockissue() {
    const wh = select('warehouse_id', await docOpts('warehouse', 'ACTIVE'), { required: true });
    const item = select('stock_item_id', await docOpts('stock_item', 'ACTIVE'), { required: true });
    const proj = select('project_id', projectOpts(), { required: true });
    const qty = input('quantity', { inputmode: 'decimal', required: true });
    const date = input('issue_date', { type: 'date', value: today(), required: true });
    const acct = select('expense_account_id', accountOpts(['EXPENSE']), { required: true });
    const cc = select('cost_code_id', [], { required: true });
    const loadCC = async () => {
      cc.textContent = '';
      if (!proj.value) return;
      for (const c of (await api('GET', `/v1/projects/${proj.value}/cost-codes`)).cost_codes) cc.append(h('option', { value: c.id }, `${c.code} ${c.name}`));
    };
    proj.addEventListener('change', () => loadCC().catch(showError));
    formPage('Issue stock to a project', 'The site engineer or project manager approves the issue; its cost (FIFO or average) is computed then and charged to the cost code.', [
      h('div', { class: 'grid' }, field('Warehouse', wh), field('Stock item', item), field('Quantity', qty), field('Project', proj), field('Cost code', cc),
        field('Expense account', acct), field('Issue date', date))], 'Request issue', async () => {
      const res = await api('POST', '/v1/stock-issues', { warehouse_id: wh.value, stock_item_id: item.value, project_id: proj.value, cost_code_id: cc.value,
        expense_account_id: acct.value, quantity: qty.value.trim(), issue_date: date.value });
      created('stock_issue', res, 'Stock issue');
    });
    await loadCC();
  },

  async stockcount() {
    const wh = select('warehouse_id', await docOpts('warehouse', 'ACTIVE'), { required: true });
    const item = select('stock_item_id', await docOpts('stock_item', 'ACTIVE'), { required: true });
    const qty = input('counted_qty', { inputmode: 'decimal', required: true });
    const date = input('count_date', { type: 'date', value: today(), required: true });
    const acct = select('variance_account_id', accountOpts(['EXPENSE']), { required: true });
    formPage('Record a stock count', 'The book quantity is taken when the count is recorded; finance approves the adjustment, and a count that has become stale is refused.', [
      h('div', { class: 'grid' }, field('Warehouse', wh), field('Stock item', item), field('Counted quantity', qty), field('Count date', date), field('Variance account', acct))],
    'Record count', async () => {
      const res = await api('POST', '/v1/stock-counts', { warehouse_id: wh.value, stock_item_id: item.value, counted_qty: qty.value.trim(),
        variance_account_id: acct.value, count_date: date.value });
      created('stock_count', res, 'Stock count');
    });
  },

  async policy() {
    const ent = select('legal_entity_id', entityOpts(), { required: true });
    const f = (n, v) => input(n, { inputmode: 'decimal', value: v, required: true });
    const tol = f('price_tolerance_pct', '0.02'), over = f('over_receipt_pct', '0.05'), vat = f('vat_rate', '0.15');
    const hv = f('high_value_po_threshold', '5000000'), dual = f('dual_payment_threshold', '500000');
    const acc = (n, types) => select(n, accountOpts(types), { required: true });
    const grni = acc('grni_account_id', ['LIABILITY']), ap = acc('ap_account_id', ['LIABILITY']), vin = acc('vat_input_account_id', ['ASSET']), ppv = acc('ppv_account_id', ['EXPENSE']);
    formPage('Propose P2P policy', 'Tolerances, thresholds and posting accounts. Takes effect only after another person approves it. Rates are tenant configuration, not tax advice.', [
      h('div', { class: 'grid' }, field('Legal entity', ent), field('Price tolerance (fraction)', tol, '0.02 = 2%'), field('Over-receipt allowance (fraction)', over),
        field('VAT rate (fraction)', vat), field('High-value PO threshold', hv), field('Dual-approval payment threshold', dual),
        field('GRNI account', grni), field('Accounts payable account', ap), field('VAT input account', vin), field('Price variance account', ppv))], 'Propose policy', async () => {
      const res = await api('POST', '/v1/p2p/policies', { legal_entity_id: ent.value, price_tolerance_pct: tol.value, over_receipt_pct: over.value, vat_rate: vat.value,
        high_value_po_threshold: hv.value, dual_payment_threshold: dual.value, grni_account_id: grni.value, ap_account_id: ap.value, vat_input_account_id: vin.value, ppv_account_id: ppv.value });
      created('p2p_policy', res, 'Policy');
    });
  },
};

// ---------- journals ----------
async function renderJournals() {
  const p2pOnly = h('input', { type: 'checkbox', id: nextId('c'), checked: true });
  const fetchJ = async (status) => (p2pOnly.checked
    ? (await Promise.all(['P2P_', 'AR_', 'STK_'].map((p) => api('GET', `/v1/journals?status=${status}&source_prefix=${p}`)))).flatMap((r) => r.journals)
    : (await api('GET', `/v1/journals?status=${status}`)).journals);
  const holder = h('div');
  page('Journals', 'Subledger documents create draft journals. A finance manager approves them and a controller posts them; neither can be the document’s creator.',
    h('div', { class: 'toolbar' }, h('div', { class: 'check' }, p2pOnly, h('label', { for: p2pOnly.id }, 'Subledger journals only (procure-to-pay, receivables, stock)'))), holder);
  const load = async () => {
    holder.textContent = '';
    const sections = [['DRAFT', 'journal.approve', 'approve-batch', 'Approve selected'], ['APPROVED', 'journal.post', 'post-batch', 'Post selected']];
    for (const [status, perm, path, label] of sections) {
      const js = await fetchJ(status);
      const can = S.can.has(perm);
      const boxes = new Map();
      const all = h('input', { type: 'checkbox', 'aria-label': `Select all ${status.toLowerCase()} journals` });
      all.addEventListener('change', () => boxes.forEach((b) => { b.checked = all.checked; }));
      const cols = [
        can ? { label: all, cell: (j) => { const b = h('input', { type: 'checkbox', 'aria-label': `Select journal ${j.source_ref || j.id.slice(0, 8)}` }); boxes.set(j.id, b); return b; } } : null,
        { label: 'Source', cell: (j) => `${j.source_type} ${j.source_ref || ''}` },
        { label: 'Description', cell: (j) => j.description },
        { label: 'Date', cell: (j) => (j.business_event_at || '').slice(0, 10) },
        { label: 'Debits', num: true, cell: (j) => money(j.debits) },
        { label: 'Created by', cell: (j) => j.created_by },
        status === 'APPROVED' ? { label: 'Approved by', cell: (j) => j.approved_by || '' } : null,
      ].filter(Boolean);
      const out = h('div');
      const btn = can && js.length ? h('button', { type: 'button' }, label) : null;
      if (btn) btn.addEventListener('click', async () => {
        clearError();
        const ids = [...boxes].filter(([, b]) => b.checked).map(([id]) => id);
        if (!ids.length) { showError(new Error('Select at least one journal.')); return; }
        btn.disabled = true;
        try {
          const res = (await api('POST', `/v1/journals/${path}`, { journal_ids: ids })).results;
          const ok = res.filter((r) => r.ok).length;
          await load();
          const failed = res.filter((r) => !r.ok);
          holder.prepend(h('p', { class: failed.length ? 'alert' : 'notice', role: 'status' }, `${ok} of ${res.length} journals done.`,
            failed.map((r) => h('span', {}, h('br'), `${r.journal_id.slice(0, 8)}: ${r.error}`))));
          say(`${ok} of ${res.length} journals done.`);
        } catch (e) { btn.disabled = false; showError(e); }
      });
      holder.append(h('div', { class: 'pagehead' }, h('h2', { class: 'section' }, status === 'DRAFT' ? 'Waiting for approval' : 'Approved, waiting to post'),
        exportBar(`/v1/journals?status=${status}`, `Journals — ${status === 'DRAFT' ? 'waiting for approval' : 'approved, waiting to post'}`)),
        ...[table(`${status === 'DRAFT' ? 'Draft' : 'Approved'} journals (${js.length})`, cols, js, 'None.'), btn ? h('div', { class: 'actions' }, btn) : null, out].filter(Boolean));
    }
  };
  p2pOnly.addEventListener('change', () => load().catch(showError));
  await load();
}

// ---------- bank ----------
async function renderBank() {
  const parts = [];
  if (S.can.has('bank.import')) {
    const banks = (await api('GET', '/v1/p2p/company_bank_account?status=ACTIVE')).items;
    const file = h('input', { type: 'file', name: 'statement', accept: 'application/json,.json', required: true });
    const preview = h('div');
    let raw = null;
    file.addEventListener('change', async () => {
      preview.textContent = '';
      raw = null;
      const f = file.files[0];
      if (!f) return;
      if (f.size > 900000) { showError(new Error('Statement file is too large (limit 900 kB).')); return; }
      raw = await f.text();
      try {
        const st = JSON.parse(raw);
        preview.append(table(`Statement ${st.statement_no || ''} — ${(st.lines || []).length} lines`, [
          { label: 'Date', cell: (l) => l.booking_date }, { label: 'Reference', cell: (l) => l.reference }, { label: 'Counterparty', cell: (l) => l.counterparty },
          { label: 'Amount', num: true, cell: (l) => money(l.amount) }], st.lines || []));
        if (st.company_bank_id && !banks.some((b) => b.id === st.company_bank_id)) showError(new Error('The file names a bank account that is not an active company account.'));
      } catch { showError(new Error('The file is not valid JSON.')); raw = null; }
    });
    const btn = h('button', { type: 'button' }, 'Import statement');
    btn.addEventListener('click', async () => {
      clearError();
      if (!raw) { showError(new Error('Choose a statement file first.')); file.focus(); return; }
      btn.disabled = true;
      try {
        const res = await api('POST', '/v1/bank-statements', undefined, raw);
        say('Statement imported.');
        await renderBank();
        $('view').insertBefore(h('p', { class: 'notice', role: 'status' }, `Statement imported (${res.id.slice(0, 8)}). The file’s SHA-256 digest is recorded with the import.`), $('view').children[1]);
      } catch (e) { btn.disabled = false; showError(e); }
    });
    parts.push(h('div', { class: 'panel' }, h('h2', { class: 'section' }, 'Import a statement'),
      h('p', { class: 'hint' }, 'Upload the bank’s statement file in SERK JSON form (company_bank_id, statement_no, statement_date, opening_balance, closing_balance, lines[booking_date, amount, reference, counterparty]). The exact bytes are hashed and recorded.'),
      field('Statement file', file), preview, h('div', { class: 'actions' }, btn)));
  }
  const sts = (await api('GET', '/v1/p2p/bank_statement')).items;
  parts.push(table(`Statements (${sts.length})`, [
    { label: 'Statement', cell: (s) => s.number }, { label: 'Account', cell: (s) => s.label }, { label: 'Status', cell: (s) => chip(s.status) },
    { label: 'Closing balance', num: true, cell: (s) => money(s.amount) }, { label: 'Imported by', cell: (s) => s.created_by },
    { label: 'Action', cell: (s) => (S.can.has('bank.reconcile') && s.status === 'OPEN' ? reconcileButton(s) : '') },
  ], sts, 'No statements imported yet.'));
  parts.push(h('div', { class: 'toolbar' }, h('span', { class: 'spacer' }), exportBar('/v1/p2p/bank_statement', 'Bank statements')));
  page('Bank statements', 'Import statements and reconcile them automatically against released payments. Unmatched lines are left for investigation, never forced.', ...parts);
}
function reconcileButton(s) {
  const b = h('button', { type: 'button', 'aria-label': `Reconcile statement ${s.number}` }, 'Reconcile');
  b.addEventListener('click', async () => {
    clearError();
    b.disabled = true;
    try {
      const r = await api('POST', `/v1/bank-statements/${s.id}/reconcile`);
      await renderBank();
      const v = $('view');
      v.insertBefore(h('div', { class: 'panel', role: 'status' }, h('p', { class: 'notice' }, `Statement ${s.number}: ${r.matched.length} matched, ${r.unmatched.length} left for investigation. Settlement journals are drafts for finance to approve.`),
        r.unmatched.length ? table('Unmatched lines', [{ label: 'Line', cell: (u) => u.line_no }, { label: 'Amount', num: true, cell: (u) => money(u.amount) },
          { label: 'Reason', cell: (u) => u.reason || '' }], r.unmatched) : null), v.children[1]);
      say(`${r.matched.length} matched, ${r.unmatched.length} unmatched.`);
    } catch (e) { b.disabled = false; showError(e); }
  });
  return b;
}

// ---------- reports ----------
async function renderRecon() {
  const ent = select('legal_entity_id', entityOpts());
  const out = h('div');
  const load = async () => {
    out.textContent = '';
    if (!ent.value) return;
    const checks = (await api('GET', `/v1/entities/${ent.value}/p2p-reconciliation`)).checks || [];
    for (const c of checks) c._class = c.difference !== '0' ? 'diff' : null;
    const breaks = checks.filter((c) => c._class).length;
    out.append(h('p', { class: breaks ? 'alert' : 'notice', role: 'status' }, breaks ? `${breaks} reconciliation difference(s) need investigation.` : 'Every subledger agrees with the general ledger.'),
      table('Subledger to general ledger', [
        { label: 'Check', cell: (c) => c.check }, { label: 'Subledger', num: true, cell: (c) => money(c.subledger) },
        { label: 'General ledger', num: true, cell: (c) => money(c.gl) }, { label: 'Difference', num: true, cell: (c) => money(c.difference) },
        { label: 'Unposted / unmatched', num: true, cell: (c) => String(c.unposted_or_unmatched) }], checks));
    const ar = (await api('GET', `/v1/entities/${ent.value}/ar-reconciliation`)).checks || [];
    for (const c of ar) c._class = c.difference !== '0' && !c.check.startsWith('Unapplied') ? 'diff' : null;
    if (ar.length) out.append(table('Receivables to general ledger', [
      { label: 'Check', cell: (c) => c.check }, { label: 'Subledger', num: true, cell: (c) => money(c.subledger) },
      { label: 'General ledger', num: true, cell: (c) => (c.check.startsWith('Unapplied') ? '' : money(c.gl)) },
      { label: 'Difference', num: true, cell: (c) => (c.check.startsWith('Unapplied') ? '' : money(c.difference)) },
      { label: 'Unposted / unapplied', num: true, cell: (c) => String(c.unposted_or_unmatched) }], ar));
    const stk = (await api('GET', `/v1/entities/${ent.value}/stock-reconciliation`)).checks || [];
    for (const c of stk) c._class = c.difference !== '0' && !c.check.startsWith('Received') ? 'diff' : null;
    if (stk.length) out.append(table('Inventory to general ledger', [
      { label: 'Check', cell: (c) => c.check }, { label: 'Subledger', num: true, cell: (c) => money(c.subledger) },
      { label: 'General ledger', num: true, cell: (c) => (c.check.startsWith('Received') ? '' : money(c.gl)) },
      { label: 'Difference', num: true, cell: (c) => (c.check.startsWith('Received') ? '' : money(c.difference)) },
      { label: 'Unposted / open', num: true, cell: (c) => String(c.unposted_or_unmatched) }], stk));
    const arBreaks = ar.filter((c) => c._class).length + stk.filter((c) => c._class).length;
    if (arBreaks) out.prepend(h('p', { class: 'alert', role: 'status' }, `${arBreaks} receivables or inventory difference(s) need investigation.`));
  };
  ent.addEventListener('change', () => load().catch(showError));
  const entName = () => (S.ref.legal_entities.find((e) => e.id === ent.value) || {}).name || '';
  const rx = (path, t) => exportBar(() => `/v1/entities/${ent.value}/${path}`, () => `${t} — ${entName()}`, { entity: () => ent.value });
  page('Reconciliation', 'GRNI, payables, payments in transit, bank, receivables, retention and advances compared with posted general-ledger balances.',
    h('div', { class: 'toolbar' }, field('Legal entity', ent), h('span', { class: 'spacer' }),
      h('div', { class: 'inline' }, rx('p2p-reconciliation', 'Payables reconciliation'), rx('ar-reconciliation', 'Receivables reconciliation'), rx('stock-reconciliation', 'Inventory reconciliation'))), out);
  await load();
}

async function renderCost() {
  const proj = select('project_id', projectOpts());
  const out = h('div');
  const load = async () => {
    out.textContent = '';
    if (!proj.value) return;
    const rows = (await api('GET', `/v1/projects/${proj.value}/cost-report`)).cost_codes;
    out.append(table('Budget, commitments and actuals by cost code', [
      { label: 'Cost code', cell: (r) => r.cost_code }, { label: 'Budget', num: true, cell: (r) => money(r.budget) },
      { label: 'Committed', num: true, cell: (r) => money(r.committed) }, { label: 'Reserved', num: true, cell: (r) => money(r.reserved) },
      { label: 'Received', num: true, cell: (r) => money(r.received) }, { label: 'Invoiced', num: true, cell: (r) => money(r.invoiced) },
      { label: 'Actual (posted)', num: true, cell: (r) => money(r.actual_posted) }, { label: 'Available', num: true, cell: (r) => money(r.available) }], rows, 'No budgeted cost codes.'));
  };
  proj.addEventListener('change', () => load().catch(showError));
  const projName = () => { const p = S.ref.projects.find((x) => x.id === proj.value); return p ? `${p.code} ${p.name}` : ''; };
  page('Project cost report', 'Approved BOQ budget against commitments (approved POs), receipts, invoices and posted actuals.',
    h('div', { class: 'toolbar' }, field('Project', proj), h('span', { class: 'spacer' }), exportBar(() => `/v1/projects/${proj.value}/cost-report`, () => `Project cost report — ${projName()}`)), out);
  await load();
}

// ---------- earned value ----------
async function renderEVM() {
  const proj = select('project_id', projectOpts());
  const at = input('status_date', { type: 'date', value: today() });
  const out = h('div');
  let seq = 0;
  const load = async () => {
    const mine = ++seq;
    out.textContent = '';
    if (!proj.value || !at.value) return;
    let r;
    try { r = await api('GET', `/v1/projects/${proj.value}/evm?status_date=${at.value}`); } catch (e) {
      if (mine !== seq) return;
      if (e.status === 404) { out.replaceChildren(h('p', { class: 'empty' }, 'The project has no baseline schedule.')); return; }
      throw e;
    }
    if (mine !== seq) return;
    out.textContent = '';
    const ratio = (x) => (x == null ? 'not defined' : Number(x).toFixed(4));
    out.append(table(`Earned value at ${at.value}${r.progress_date ? ' (progress reported ' + r.progress_date.slice(0, 10) + ')' : ' (no approved progress)'}`, [
      { label: 'Measure', cell: (x) => x[0] }, { label: 'Value', num: true, cell: (x) => x[1] }], [
      ['Budget at completion (BAC)', money(r.bac)], ['Planned value (PV)', money(r.pv)], ['Earned value (EV)', money(r.ev)],
      ['Actual cost (AC, posted)', money(r.ac)], ['Schedule variance (EV - PV)', money(r.sv)], ['Cost variance (EV - AC)', money(r.cv)],
      ['Schedule performance index (EV / PV)', ratio(r.spi)], ['Cost performance index (EV / AC)', ratio(r.cpi)]]));
  };
  for (const el of [proj, at]) el.addEventListener('change', () => load().catch(showError));
  page('Earned value', 'From the approved baseline (PV spread over each activity\'s working days), the latest approved progress (EV) and the posted ledger cost on the project (AC).',
    h('div', { class: 'toolbar' }, field('Project', proj), field('Status date', at), h('span', { class: 'spacer' }),
      exportBar(() => `/v1/projects/${proj.value}/evm?status_date=${at.value}`, () => { const p = S.ref.projects.find((x) => x.id === proj.value); return `Earned value — ${p ? p.code + ' ' + p.name : ''} at ${at.value}`; })), out);
  await load();
}

// ---------- field devices ----------
async function renderDevices() {
  const r = await api('GET', '/v1/site/devices');
  const out = h('div', { 'aria-live': 'polite' });
  const label = input('label', { type: 'text', maxlength: '100', required: true });
  const reg = h('form', { class: 'panel', novalidate: true }, field('Device name', label, 'Registering a device needs a recent multi-factor sign-in. Its key is shown once.'),
    h('div', { class: 'actions' }, h('button', { type: 'submit' }, 'Register a device')));
  reg.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    clearError();
    if (!label.value.trim()) { showError(new Error('Name the device.')); label.focus(); return; }
    try {
      const d = await api('POST', '/v1/site/devices', { label: label.value.trim() });
      out.replaceChildren(h('div', { class: 'notice', role: 'status' }, h('p', {}, `Device registered. Enter this key in the field app now; it is not shown again.`),
        h('pre', { class: 'secret' }, `device id  ${d.id}\ndevice key ${d.secret}`)));
      label.value = '';
    } catch (e) { showError(e); }
  });
  const revoke = (d) => {
    if (d.status !== 'ACTIVE') return '';
    const reason = input('reason', { type: 'text', maxlength: '500', 'aria-label': `Reason for revoking ${d.label}` });
    const btn = h('button', { type: 'button', class: 'danger' }, 'Revoke');
    btn.addEventListener('click', async () => {
      clearError();
      if (reason.value.trim().length < 5) { showError(new Error('Give a reason of at least 5 characters.')); reason.focus(); return; }
      btn.disabled = true;
      try { await api('POST', `/v1/site/devices/${d.id}/revoke`, { reason: reason.value.trim() }); say(`${d.label} revoked.`); await renderDevices(); } catch (e) { btn.disabled = false; showError(e); }
    });
    return h('span', { class: 'inline' }, reason, btn);
  };
  page('Field devices', 'Devices that may synchronise site records prepared offline. A revoked device can never synchronise again, including records it queued before the revocation.',
    h('div', { class: 'toolbar' }, h('span', { class: 'spacer' }), exportBar('/v1/site/devices', 'Field devices')),
    S.can.has('site.device.register') ? reg : null, out,
    table(`Devices (${r.items.length})`, [
      { label: 'Device', cell: (d) => d.label }, { label: 'Person', cell: (d) => d.user_id }, { label: 'Status', cell: (d) => chip(d.status) },
      { label: 'Last sync', cell: (d) => (d.last_sync_at ? when(d.last_sync_at) : 'never') }, { label: 'Commands', num: true, cell: (d) => String(d.last_seq) },
      { label: 'Registered', cell: (d) => when(d.registered_at) }, { label: 'Action', cell: revoke }], r.items, 'No devices registered.'));
}

// ---------- stock ----------
async function renderStock() {
  const ent = select('legal_entity_id', entityOpts());
  const out = h('div');
  const load = async () => {
    out.textContent = '';
    if (!ent.value) return;
    const lines = (await api('GET', `/v1/entities/${ent.value}/stock-on-hand`)).lines || [];
    out.append(table(`Stock on hand (${lines.length})`, [
      { label: 'Item', cell: (l) => `${l.item_code} ${l.item_name}` }, { label: 'Warehouse', cell: (l) => l.warehouse_code },
      { label: 'Valuation', cell: (l) => l.valuation_method }, { label: 'Quantity', num: true, cell: (l) => `${l.qty} ${l.unit}` },
      { label: 'Unit cost', num: true, cell: (l) => money(l.unit_cost) }, { label: 'Value', num: true, cell: (l) => money(l.value) }], lines, 'No stock on hand.'));
  };
  ent.addEventListener('change', () => load().catch(showError));
  const tools = h('div', { class: 'toolbar' }, field('Legal entity', ent),
    S.can.has('stock.issue') ? h('a', { class: 'btn', href: '#/new/stockissue' }, 'Issue stock') : null,
    S.can.has('stock.count') ? h('a', { class: 'btn ghost', href: '#/new/stockcount' }, 'Record a count') : null,
    h('span', { class: 'spacer' }), exportBar(() => `/v1/entities/${ent.value}/stock-on-hand`, () => `Stock on hand — ${(S.ref.legal_entities.find((e) => e.id === ent.value) || {}).name || ''}`, { entity: () => ent.value }));
  page('Stock on hand', 'Quantities and values by item and warehouse (the stores of your projects, or every warehouse for tenant-wide roles).', tools, out);
  await load();
}


// ---------- export (PDF / Word / Excel) ----------
// The server renders the file from the same authorised read the screen
// uses, stamped with the company, the person and the time.
function exportBar(src, title, opts = {}) {
  const val = (x) => (typeof x === 'function' ? x() : x);
  const wrap = h('div', { class: 'export', role: 'group', 'aria-label': 'Export' }, h('span', { class: 'lbl' }, 'Export'));
  for (const [fmt, label] of [['pdf', 'PDF'], ['docx', 'Word'], ['xlsx', 'Excel']]) {
    const b = h('button', { type: 'button', class: 'ghost', 'data-export': fmt, 'aria-label': `Export as ${label}` }, label);
    b.addEventListener('click', async () => {
      clearError();
      b.disabled = true;
      try {
        const qs = new URLSearchParams({ src: val(src), format: fmt, title: val(title) });
        if (opts.entity && opts.entity()) qs.set('entity', opts.entity());
        const r = await fetch('/v1/export?' + qs, { headers: { Authorization: 'Bearer ' + S.token } });
        if (!r.ok) {
          const d = await r.json().catch(() => ({}));
          const e = d.error || {};
          throw new ApiError(r.status, e.code || 'error', e.message || r.statusText, r.headers.get('WWW-Authenticate'));
        }
        const blob = await r.blob();
        const name = (/filename="([^"]+)"/.exec(r.headers.get('Content-Disposition') || '') || [])[1] || `serk-export.${fmt}`;
        const url = URL.createObjectURL(blob);
        const a = h('a', { href: url, download: name, hidden: true });
        document.body.append(a);
        a.click();
        a.remove();
        setTimeout(() => URL.revokeObjectURL(url), 60000);
        say(`${label} file ready: ${name}`);
      } catch (e) { showError(e); } finally { b.disabled = false; }
    });
    wrap.append(b);
  }
  return wrap;
}

// ---------- reports ----------
const REPORTS = [
  ['#/tb', 'Trial balance', 'Posted debits and credits by account at any date, with the balance check.', 'journal.read'],
  ['#/aging/ap', 'Payables aging', 'Approved supplier invoices still open, by days past due.', 'scope.tenant_wide'],
  ['#/aging/ar', 'Receivables aging', 'Approved customer invoices still open after receipts and credit notes.', 'scope.tenant_wide'],
  ['#/recon', 'Reconciliation', 'Every subledger against the general ledger: payables, bank, receivables, inventory.', 'journal.read'],
  ['#/cost', 'Project cost report', 'Budget, commitments, receipts, invoices and posted actuals by cost code.', 'p2p.read'],
  ['#/evm', 'Earned value', 'Planned value, earned value and actual cost from the baseline schedule.', 'p2p.read'],
  ['#/stock', 'Stock on hand', 'Quantities and values by item and warehouse.', 'p2p.read'],
  ['#/journals', 'Journals', 'Draft and approved journals awaiting decision.', 'journal.read'],
];
async function renderReports() {
  const grid = h('div', { class: 'reportgrid' });
  for (const [href, t, d, perm] of REPORTS) {
    if (!allowed(perm)) continue;
    grid.append(h('a', { class: 'card', href }, h('h3', {}, t), h('p', {}, d)));
  }
  page('Reports', 'Every report and every list can be exported as PDF, Word or Excel with the company letterhead.', grid,
    h('p', { class: 'foot-note' }, 'Exports contain only what you may see. Each export is recorded with your name and the time.'));
}

function entityToolbar(ent, at, extra) {
  return h('div', { class: 'toolbar' }, field('Legal entity', ent), field('As at', at), h('span', { class: 'spacer' }), extra);
}

async function renderTB() {
  const ent = select('legal_entity_id', entityOpts());
  const at = input('as_of', { type: 'date', value: today() });
  const out = h('div');
  const src = () => `/v1/reports/trial-balance?entity=${ent.value}&as_of=${at.value}`;
  const load = async () => {
    out.textContent = '';
    if (!ent.value || !at.value) return;
    const r = await api('GET', src());
    const rows = r.accounts.filter((a) => a.debit !== '0' || a.credit !== '0');
    rows.push({ _class: 'total', account_code: '', account_name: 'Total', account_type: '', debit: r.total_debit, credit: r.total_credit, balance: r.difference });
    out.append(h('p', { class: r.balanced ? 'notice' : 'alert', role: 'status' }, r.balanced ? 'Debits equal credits: the ledger balances.' : `Out of balance by ${money(r.difference)}.`),
      table(`Trial balance at ${r.as_of}`, [
        { label: 'Code', cell: (a) => h('span', { class: 'ref' }, a.account_code) }, { label: 'Account', cell: (a) => a.account_name },
        { label: 'Type', cell: (a) => (a.account_type ? words(a.account_type.toLowerCase()) : '') },
        { label: 'Debit', num: true, cell: (a) => money(a.debit) }, { label: 'Credit', num: true, cell: (a) => money(a.credit) },
        { label: 'Balance', num: true, cell: (a) => money(a.balance) }], rows, 'No posted entries.'));
  };
  for (const el of [ent, at]) el.addEventListener('change', () => load().catch(showError));
  page('Trial balance', 'Posted journal lines summed by account up to the date chosen. Only posted entries count.',
    entityToolbar(ent, at, exportBar(src, () => `Trial balance at ${at.value}`, { entity: () => ent.value })), out);
  await load();
}

async function renderAging(kind) {
  const ar = kind === 'ar';
  const ent = select('legal_entity_id', entityOpts());
  const at = input('as_of', { type: 'date', value: today() });
  const out = h('div');
  const title = ar ? 'Receivables aging' : 'Payables aging';
  const src = () => `/v1/reports/${kind}-aging?entity=${ent.value}&as_of=${at.value}`;
  const buckets = [['not_due', 'Not due'], ['d1_30', '1–30'], ['d31_60', '31–60'], ['d61_90', '61–90'], ['over_90', 'Over 90'], ['open', 'Open']];
  const load = async () => {
    out.textContent = '';
    if (!ent.value || !at.value) return;
    const r = await api('GET', src());
    const parties = [...r.by_party, { ...r.total, _class: 'total' }];
    out.append(table(`${title} by ${ar ? 'customer' : 'supplier'} at ${r.as_of}`, [
      { label: ar ? 'Customer' : 'Supplier', cell: (p) => p.party },
      ...buckets.map(([k, l]) => ({ label: l, num: true, cell: (p) => money(p[k]) }))], parties, 'Nothing open.'),
    table(`Open invoices (${r.items.length})`, [
      { label: ar ? 'Customer' : 'Supplier', cell: (i) => i.party }, { label: 'Invoice', cell: (i) => h('span', { class: 'ref' }, i.document) },
      { label: 'Invoice date', cell: (i) => i.invoice_date }, { label: 'Due', cell: (i) => i.due_date },
      { label: 'Days overdue', num: true, cell: (i) => (i.days_overdue ? String(i.days_overdue) : '') },
      { label: 'Open', num: true, cell: (i) => `${money(i.open)} ${i.currency}` }], r.items, 'Nothing open.'));
  };
  for (const el of [ent, at]) el.addEventListener('change', () => load().catch(showError));
  page(title, ar ? 'Approved customer invoices less confirmed receipts and approved credit notes, by days past due.'
    : 'Approved supplier invoices less released payments, by days past due.',
  entityToolbar(ent, at, exportBar(src, () => `${title} at ${at.value}`, { entity: () => ent.value })), out);
  await load();
}

// ---------- notifications ----------
// The bell counts the items waiting for you (the same queues as "My work"),
// refreshed every minute while the tab is visible. New items can also raise
// a desktop notification if you allow it. Nothing is ever approved
// automatically: notifications only point you at work.
const BELL = { timer: null, items: [], server: [], total: null, open: false };
const seenKey = () => `serk-seen-${S.me ? S.me.tenant_id + '/' + S.me.user_id : ''}`;
function readSeen() { try { return JSON.parse(localStorage.getItem(seenKey()) || '{}'); } catch { return {}; } }
function writeSeen(v) { try { localStorage.setItem(seenKey(), JSON.stringify(v)); } catch { /* storage unavailable */ } }
function setBell(items) {
  const prev = BELL.total;
  BELL.items = items;
  BELL.total = items.reduce((n, q) => n + (q.n || 0), 0) + (BELL.server || []).filter((n) => !n.read_at).length;
  const c = $('bell-count');
  c.textContent = BELL.total > 99 ? '99+' : String(BELL.total);
  c.hidden = !BELL.total;
  $('bell').setAttribute('aria-label', `Notifications: ${BELL.total} item${BELL.total === 1 ? '' : 's'} waiting`);
  if (prev != null && BELL.total > prev && document.hidden && 'Notification' in window && Notification.permission === 'granted') {
    const grew = items.filter((q) => q.n).map((q) => q.label).slice(0, 3).join(', ');
    try { new Notification('SERK Construction', { body: `${BELL.total - prev} new item(s) waiting: ${grew}`, tag: 'serk-work' }); } catch { /* not allowed here */ }
  }
  if (BELL.open) renderDrawer();
}
async function pollBell() {
  if (!S.token || document.hidden) return;
  try {
    const [queues, server] = await Promise.all([workQueues(), api('GET', '/v1/notifications?limit=50').catch(() => ({ items: [] }))]);
    BELL.server = server.items || [];
    setBell(queues);
  } catch { /* next poll */ }
}
function startBell() {
  $('bell').hidden = false;
  stopBell(true);
  pollBell();
  BELL.timer = setInterval(pollBell, 60000);
}
function stopBell(keep) {
  if (BELL.timer) clearInterval(BELL.timer);
  BELL.timer = null;
  if (!keep) { $('bell').hidden = true; $('bell-count').hidden = true; BELL.total = null; closeDrawer(); }
}
function renderDrawer() {
  const d = $('drawer');
  const seen = readSeen();
  const list = BELL.items.filter((q) => q.n);
  const enable = 'Notification' in window && Notification.permission === 'default'
    ? h('button', { type: 'button', class: 'ghost' }, 'Enable desktop alerts') : null;
  if (enable) enable.addEventListener('click', async () => { try { await Notification.requestPermission(); } catch { /* ignored */ } renderDrawer(); });
  const server = (BELL.server || []).slice(0, 20);
  const serverList = server.length ? h('ul', {}, server.map((n) => h('li', {}, h('a', { href: n.href || '#/home', on: { click: async () => {
    closeDrawer();
    if (!n.read_at) { try { await api('POST', `/v1/notifications/${n.id}/read`); n.read_at = new Date().toISOString(); } catch { /* ignore */ } }
  } } },
    h('span', { class: n.read_at ? 'dot seen' : 'dot', 'aria-hidden': 'true' }),
    h('span', {}, h('span', { class: n.severity === 'critical' ? 'chip bad' : n.severity === 'warn' ? 'chip warn' : 'chip' }, n.severity), ' ', n.title,
      n.read_at ? null : h('span', { class: 'sr' }, ' (unread)')),
    h('span', { class: 'hint' }, when(n.created_at).split(',')[0]))))) : null;
  d.replaceChildren(
    h('header', {}, h('h2', { id: 'drawer-title' }, 'Notifications'), h('button', { type: 'button', class: 'ghost', 'aria-label': 'Close notifications', on: { click: closeDrawer } }, 'Close')),
    serverList ? h('h3', { class: 'drawer-sub' }, 'Alerts') : null, serverList,
    h('h3', { class: 'drawer-sub' }, 'Waiting for you'),
    list.length ? h('ul', {}, list.map((q) => h('li', {}, h('a', { href: q.href, on: { click: closeDrawer } },
      h('span', { class: (seen[q.label] || 0) >= q.n ? 'dot seen' : 'dot', 'aria-hidden': 'true' }), h('span', {}, q.label,
        (seen[q.label] || 0) < q.n ? h('span', { class: 'sr' }, ' (new)') : null), h('span', { class: 'count' }, String(q.n))))))
      : h('p', { class: 'empty' }, 'You are all caught up.'),
    h('div', { class: 'foot' }, h('a', { href: '#/home', on: { click: closeDrawer } }, 'Open my work'), h('span', { class: 'spacer' }), enable,
      'Notification' in window && Notification.permission === 'granted' ? h('span', { class: 'hint' }, 'Desktop alerts on') : null));
  d.setAttribute('aria-labelledby', 'drawer-title');
}
function openDrawer() {
  BELL.open = true;
  renderDrawer();
  $('drawer').hidden = false;
  $('bell').setAttribute('aria-expanded', 'true');
  const seen = {};
  for (const q of BELL.items) seen[q.label] = q.n || 0;
  setTimeout(() => writeSeen(seen), 1500);
  const first = $('drawer').querySelector('a, button');
  if (first) first.focus();
}
function closeDrawer() {
  if (!BELL.open) return;
  BELL.open = false;
  $('drawer').hidden = true;
  $('bell').setAttribute('aria-expanded', 'false');
}
$('bell').addEventListener('click', () => (BELL.open ? closeDrawer() : openDrawer()));
document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && BELL.open) { closeDrawer(); $('bell').focus(); } });
document.addEventListener('click', (e) => { if (BELL.open && !$('drawer').contains(e.target) && !$('bell').contains(e.target)) closeDrawer(); });
document.addEventListener('visibilitychange', () => { if (!document.hidden) pollBell(); });


// ---------- company branding ----------
// The vendor is SERK Construction OS; the construction company using it is
// the tenant. Its name leads once signed in.
function brandCompany() {
  const name = document.querySelector('.brand .name');
  const tag = document.querySelector('.brand .tag');
  if (S.company && S.company.display_name) {
    name.textContent = S.company.display_name;
    tag.textContent = 'SERK Construction OS';
  } else {
    name.textContent = 'SERK Construction OS';
    tag.textContent = 'Operations';
  }
}

// ---------- ask ----------
const SUGGESTED = ['Which projects are over budget?', 'Which activities are behind schedule?', 'Which purchase orders have not been delivered?',
  'Which invoices are awaiting approval?', 'What is the cash requirement for the next 90 days?', 'Which projects have deteriorating margins?',
  'What changed last week?', 'Are there duplicate invoices or suspicious payments?'];
async function renderAsk() {
  const q = h('input', { type: 'text', name: 'question', maxlength: '500', autocomplete: 'off', placeholder: 'Ask about your projects, money or risks' });
  const out = h('div', { 'aria-live': 'polite' });
  const ask = async (question) => {
    clearError();
    out.replaceChildren(h('p', { class: 'hint' }, 'Working it out from your records…'));
    try {
      const a = await api('POST', '/v1/assistant/ask', { question });
      const lines = a.text.split('\n');
      out.replaceChildren(h('div', { class: 'panel answer' },
        h('p', { class: 'eyebrow' }, `${words(a.intent)} · data as of ${a.freshness}${a.phrased_by_model ? ' · phrased by a language model from these facts' : ''}`),
        h('div', { class: 'answer-text' }, lines.map((l) => h('p', {}, l))),
        a.assumptions && a.assumptions.length ? h('details', {}, h('summary', {}, 'Assumptions and method'), h('ul', {}, a.assumptions.map((x) => h('li', {}, x)))) : null,
        a.missing && a.missing.length ? h('p', { class: 'notice' }, 'Missing or not assessable: ', a.missing.join('; ')) : null,
        a.sources && a.sources.length ? h('div', {}, h('h2', { class: 'section' }, 'Sources'), h('ul', { class: 'sources' }, a.sources.map((s) => h('li', {}, h('a', { href: s.href }, s.label))))) : null));
    } catch (e) { showError(e); out.textContent = ''; }
  };
  const form = h('form', { class: 'askbar', on: { submit: (ev) => { ev.preventDefault(); if (q.value.trim()) ask(q.value.trim()); } } },
    q, h('button', { type: 'submit' }, 'Ask'));
  page('Ask', 'Answers come from the company’s own records, with the formula, the sources and what is missing. Nothing is invented, and nothing is decided for you.',
    form, h('div', { class: 'chips' }, SUGGESTED.map((t) => h('button', { type: 'button', class: 'ghost', on: { click: () => { q.value = t; ask(t); } } }, t))), out);
  q.focus();
}

// ---------- risks ----------
const LEVEL = { high: 'chip bad', medium: 'chip warn', low: 'chip ok', unknown: 'chip' };
function findingCard(f) {
  return h('div', { class: 'panel finding' },
    h('div', { class: 'pagehead' }, h('div', {}, h('p', { class: 'eyebrow' }, f.area), h('h3', {}, f.title)), h('span', { class: LEVEL[f.level] || 'chip' }, f.level)),
    f.metric ? h('p', {}, h('strong', {}, words(f.metric)), f.value ? `: ${f.value}` : '', f.threshold ? ` (threshold ${f.threshold})` : '') : null,
    f.amounts ? h('dl', { class: 'kv' }, Object.entries(f.amounts).flatMap(([k, v]) => [h('dt', {}, words(k)), h('dd', {}, v)])) : null,
    f.advice ? h('p', { class: 'advice' }, f.advice) : null,
    f.missing && f.missing.length ? h('p', { class: 'hint' }, 'Missing: ', f.missing.join('; ')) : null,
    f.formula ? h('p', { class: 'hint' }, 'How: ', f.formula) : null,
    f.evidence && f.evidence.length ? h('p', {}, f.evidence.map((e, i) => [i ? ' · ' : '', h('a', { href: e.href }, e.label)])) : null);
}
async function renderRisk(projectId) {
  if (projectId) {
    const a = await api('GET', `/v1/intelligence/projects/${projectId}/risks`);
    const parts = [h('p', {}, h('span', { class: LEVEL[a.overall] }, `overall ${a.overall}`), ` · computed ${a.data_as_of} · ${a.algorithm}`)];
    if (a.forecast) {
      const f = a.forecast;
      parts.push(h('div', { class: 'panel' }, h('h2', { class: 'section' }, 'Forecast of final cost'),
        h('dl', { class: 'kv' }, ...[['Budget at completion (BAC)', f.bac], ['Planned value (PV)', f.pv], ['Earned value (EV)', f.ev], ['Actual cost (AC)', f.ac],
          ['SPI', f.spi || 'not defined'], ['CPI', f.cpi || 'not defined'], ['Estimate at completion (EAC)', f.eac || 'not computable'], ['Estimate to complete (ETC)', f.etc || '—'],
          ['Variance at completion (VAC)', f.vac || '—'], ['Percent complete (EV / BAC)', f.percent_complete || '—'], ['Method', f.method]].flatMap(([k, v]) => [h('dt', {}, k), h('dd', {}, v)])),
        h('details', {}, h('summary', {}, 'Assumptions'), h('ul', {}, (f.assumptions || []).map((x) => h('li', {}, x))))));
    }
    parts.push(...a.findings.map(findingCard));
    if (a.history && a.history.length) parts.push(h('p', { class: 'hint' }, 'Recorded assessments: ', a.history.map((p) => `${when(p.at).split(',')[0]} ${p.overall}`).join(' · ')));
    page(`${a.code} ${a.name} — risks`, 'Deterministic assessment from approved baselines, posted ledger cost and approved purchase orders. Every finding shows its formula and evidence.', ...parts);
    return;
  }
  const r = await api('GET', '/v1/intelligence/portfolio');
  const cards = h('div', { class: 'cards' });
  for (const a of r.projects) {
    const counts = {};
    for (const f of a.findings) counts[f.level] = (counts[f.level] || 0) + 1;
    cards.append(h('a', { class: a.overall === 'high' ? 'card hot' : 'card', href: `#/risk/${a.project_id}` },
      h('div', { class: 'pagehead' }, h('div', { class: 't' }, `${a.code} ${a.name}`), h('span', { class: LEVEL[a.overall] }, a.overall)),
      h('div', { class: 'hint' }, Object.entries(counts).map(([k, v]) => `${v} ${k}`).join(' · ')),
      a.forecast && a.forecast.eac ? h('div', { class: 'hint' }, `EAC ${a.forecast.eac} · VAC ${a.forecast.vac}`) : null));
  }
  page('Risks', `Each project assessed on schedule, cost, budget consumption and procurement (${r.algorithm}). Open a project for the formulas, evidence and advice.`,
    r.projects.length ? cards : h('p', { class: 'empty' }, 'No projects in view.'));
}

async function renderControls() {
  const ent = select('legal_entity_id', entityOpts());
  const out = h('div');
  const load = async () => {
    out.textContent = '';
    if (!ent.value) return;
    const [cash, ctl] = await Promise.all([api('GET', `/v1/intelligence/cash?entity=${ent.value}`), api('GET', `/v1/intelligence/controls?entity=${ent.value}`)]);
    out.append(h('div', { class: 'panel' }, h('div', { class: 'pagehead' }, h('h2', { class: 'section' }, '90-day cash outlook'), h('span', { class: LEVEL[cash.level] }, cash.level)),
      h('dl', { class: 'kv' }, ...[['Cash held (ledger)', cash.cash_held], ['Payables due in 90 days', `${cash.payables_due.total} (overdue ${cash.payables_due.overdue})`],
        ['Receivables due in 90 days', `${cash.receivables_due.total} (overdue ${cash.receivables_due.overdue})`], ['Net position', cash.net_90]].flatMap(([k, v]) => [h('dt', {}, k), h('dd', {}, v)])),
      h('p', { class: 'hint' }, cash.formula), h('details', {}, h('summary', {}, 'Assumptions'), h('ul', {}, cash.assumptions.map((x) => h('li', {}, x)))),
      cash.missing && cash.missing.length ? h('p', { class: 'notice' }, 'Missing: ' + cash.missing.join('; ')) : null));
    out.append(h('h2', { class: 'section' }, `Items for review (${ctl.items.length})`));
    if (!ctl.items.length) out.append(h('p', { class: 'notice' }, 'No duplicate invoice numbers and no payments just under the dual-approval threshold.'));
    for (const f of ctl.items) out.append(h('div', { class: 'panel finding' }, h('div', { class: 'pagehead' }, h('h3', {}, f.title), h('span', { class: LEVEL[f.level] }, f.level)),
      h('p', {}, f.detail), h('p', {}, f.evidence.map((e, i) => [i ? ' · ' : '', h('a', { href: e.href }, e.label)]))));
  };
  ent.addEventListener('change', () => load().catch(showError));
  page('Control review', 'Flags for a reviewer, never accusations: duplicate invoice numbers and payments just under the dual-approval threshold, plus the cash outlook.',
    h('div', { class: 'toolbar' }, field('Legal entity', ent)), out);
  await load();
}

// ---------- automation rules ----------
async function renderAutomation() {
  const [rules, cat] = await Promise.all([api('GET', '/v1/automation/rules'), api('GET', '/v1/automation/catalogue')]);
  const parts = [h('p', { class: 'notice' }, cat.note)];
  const canManage = S.can.has('automation.manage'), canActivate = S.can.has('automation.activate');
  if (canManage) {
    const code = input('code', { type: 'text', maxlength: '40', required: true, placeholder: 'AP-STALE' });
    const name = input('name', { type: 'text', maxlength: '120', required: true });
    const desc = h('textarea', { name: 'description', maxlength: '2000' });
    const kind = select('kind', cat.conditions.map((c) => ({ value: c.kind, label: c.kind })));
    const kdesc = h('p', { class: 'hint' });
    const params = h('div', { class: 'grid' });
    const role = input('notify_role', { type: 'text', maxlength: '40', placeholder: 'ap_supervisor' });
    const sev = select('severity', [{ value: 'info', label: 'info' }, { value: 'warn', label: 'warn' }, { value: 'critical', label: 'critical' }]);
    const title = input('title', { type: 'text', maxlength: '200' });
    const PARAMS = { document_stale: ['subject', 'status', 'hours'], invoice_due: ['days'], receivable_overdue: ['days'], po_overdue: [], budget_threshold: ['percent'],
      stock_below: ['item_code', 'quantity'], schedule_risk: ['ratio'], cost_risk: ['ratio'], export_volume: ['count'] };
    const inputs = {};
    const paint = () => {
      params.textContent = '';
      kdesc.textContent = (cat.conditions.find((c) => c.kind === kind.value) || {}).description || '';
      for (const k of PARAMS[kind.value] || []) { inputs[k] = input(k, { type: 'text', maxlength: '40' }); params.append(field(words(k), inputs[k])); }
    };
    kind.addEventListener('change', paint);
    paint();
    const form = h('form', { class: 'panel', novalidate: true, on: { submit: async (ev) => {
      ev.preventDefault();
      clearError();
      const when = { kind: kind.value };
      for (const k of PARAMS[kind.value] || []) {
        const v = (inputs[k].value || '').trim();
        if (!v) { showError(new Error(`Fill in ${words(k)}.`)); inputs[k].focus(); return; }
        when[k] = /^(hours|days|percent|count)$/.test(k) ? Number(v) : v;
      }
      try {
        await api('POST', '/v1/automation/rules', { code: code.value.trim().toUpperCase(), name: name.value.trim(), description: desc.value.trim(),
          body: { when, then: { notify_role: role.value.trim(), severity: sev.value, title: title.value.trim() || undefined } } });
        say('Rule proposed; someone else activates it.');
        await renderAutomation();
      } catch (e) { showError(e); }
    } } },
    h('h2', { class: 'section' }, 'Propose a rule'),
    h('div', { class: 'grid' }, field('Code', code), field('Name', name), field('Condition', kind, kdesc)), params,
    h('div', { class: 'grid' }, field('Notify role', role, 'A role name, e.g. ap_supervisor, project_manager, treasury_officer.'), field('Severity', sev), field('Title (optional)', title)),
    field('Description', desc), h('div', { class: 'actions' }, h('button', { type: 'submit' }, 'Propose rule')));
    parts.push(form);
  }
  const act = (r) => {
    const box = h('span', { class: 'inline' });
    if (r.status === 'DRAFT' && canActivate && r.created_by !== S.me.user_id) {
      const b = h('button', { type: 'button' }, 'Activate');
      b.addEventListener('click', async () => { clearError(); b.disabled = true; try { await api('POST', `/v1/automation/rules/${r.id}/activate`); say(`${r.code} active.`); await renderAutomation(); } catch (e) { b.disabled = false; showError(e); } });
      box.append(b);
    }
    if (r.status !== 'RETIRED' && (canActivate || canManage)) {
      const reason = input('reason', { type: 'text', maxlength: '500', 'aria-label': `Reason for retiring ${r.code}` });
      const b = h('button', { type: 'button', class: 'danger' }, 'Retire');
      b.addEventListener('click', async () => { clearError(); if (reason.value.trim().length < 5) { showError(new Error('Give a reason of at least 5 characters.')); reason.focus(); return; }
        b.disabled = true; try { await api('POST', `/v1/automation/rules/${r.id}/retire`, { reason: reason.value.trim() }); say(`${r.code} retired.`); await renderAutomation(); } catch (e) { b.disabled = false; showError(e); } });
      box.append(reason, b);
    }
    return box;
  };
  parts.push(table(`Rules (${rules.items.length})`, [
    { label: 'Code', cell: (r) => h('span', { class: 'ref' }, r.code) }, { label: 'Name', cell: (r) => r.name },
    { label: 'Condition', cell: (r) => { const w = r.body.when || {}; return Object.entries(w).map(([k, v]) => `${k}=${v}`).join(' '); } },
    { label: 'Then', cell: (r) => { const t = r.body.then || {}; return `notify ${t.notify_role || t.notify_user} (${t.severity})`; } },
    { label: 'Status', cell: (r) => chip(r.status) }, { label: 'Proposed by', cell: (r) => r.created_by }, { label: 'Activated by', cell: (r) => r.activated_by || '' },
    { label: 'Last run', cell: (r) => (r.last_run_at ? `${when(r.last_run_at)} · ${r.last_run_findings} finding(s)` : 'not yet') }, { label: 'Action', cell: act }], rules.items, 'No rules yet.'));
  page('Automation rules', 'Rules watch the company’s records and tell the right people. A rule is proposed by one person and activated by another; it never approves, posts, pays or releases anything.', ...parts);
}

// ---------- company settings ----------
async function renderSettings() {
  const st = await api('GET', '/v1/tenant/settings');
  const can = S.can.has('tenant.settings.manage');
  const f = {
    display_name: input('display_name', { type: 'text', maxlength: '120', value: st.display_name, required: true }),
    short_code: input('short_code', { type: 'text', maxlength: '32', value: st.short_code || '' }),
    letterhead_name: input('letterhead_name', { type: 'text', maxlength: '160', value: st.letterhead_name || '' }),
    country: input('country', { type: 'text', maxlength: '2', value: st.country }),
    timezone: input('timezone', { type: 'text', maxlength: '64', value: st.timezone }),
    locale: select('locale', [{ value: 'en', label: 'English' }, { value: 'am', label: 'Amharic (አማርኛ)' }, { value: 'ti', label: 'Tigrinya (ትግርኛ)' }]),
    export_daily_limit: input('export_daily_limit', { type: 'number', min: '1', max: '100000', value: String(st.export_daily_limit) }),
    theme_accent: input('theme_accent', { type: 'text', maxlength: '7', value: st.theme_accent || '', placeholder: '#1b4a33' }),
  };
  f.locale.value = st.locale;
  if (!can) for (const el of Object.values(f)) el.disabled = true;
  const form = h('form', { class: 'panel', novalidate: true, on: { submit: async (ev) => {
    ev.preventDefault();
    clearError();
    try {
      const body = { version: st.version };
      for (const [k, el] of Object.entries(f)) body[k] = k === 'export_daily_limit' ? Number(el.value) : el.value.trim();
      S.company = await api('PUT', '/v1/tenant/settings', body);
      brandCompany();
      say('Company settings saved.');
      await renderSettings();
    } catch (e) { showError(e); }
  } } },
  h('div', { class: 'grid' }, field('Company name', f.display_name), field('Portal code', f.short_code, 'Lowercase letters, digits and hyphens.'),
    field('Letterhead on exports', f.letterhead_name, 'Printed on every PDF, Word and Excel export.'), field('Country', f.country), field('Time zone', f.timezone),
    field('Language', f.locale, 'Interface translation to Amharic and Tigrinya is in preparation; data is stored unchanged.'),
    field('Daily export limit per person', f.export_daily_limit, 'Beyond this, exports are refused for the day and security is told.'), field('Accent colour (optional)', f.theme_accent)),
  can ? h('div', { class: 'actions' }, h('button', { type: 'submit' }, 'Save settings')) : h('p', { class: 'hint' }, 'Only a security administrator can change these.'));
  page('Company settings', `${st.display_name} on SERK Construction OS. Version ${st.version}${st.updated_by ? `, last changed by ${st.updated_by} ${when(st.updated_at)}` : ''}.`, form,
    h('div', { class: 'panel' }, h('h2', { class: 'section' }, 'Data protection'), h('ul', {},
      h('li', {}, 'Every record is isolated per company by database row-level security; a session can only ever reach its own company.'),
      h('li', {}, 'Exports carry the company letterhead, the person’s name and the time, and are counted against a daily limit.'),
      h('li', {}, 'Bank account numbers are encrypted at rest and masked everywhere; revealing one needs a fresh multi-factor sign-in and is audited.'),
      h('li', {}, 'Every approval is a signed human decision verified by the database. Automation and the assistant can only read and notify.'))));
}

// ---------- theme: day (green on cream) / night (cream on green) ----------
const THEME_KEY = 'serk-theme';
const SVGNS = 'http://www.w3.org/2000/svg';
function icon(paths) {
  const svg = document.createElementNS(SVGNS, 'svg');
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('aria-hidden', 'true');
  for (const d of paths) { const p = document.createElementNS(SVGNS, 'path'); p.setAttribute('d', d); svg.append(p); }
  return svg;
}
const MOON = ['M20 14.5A8 8 0 0 1 9.5 4a8 8 0 1 0 10.5 10.5z'];
const SUN = ['M12 8a4 4 0 1 0 0 8a4 4 0 1 0 0-8z', 'M12 2v2', 'M12 20v2', 'M4.9 4.9l1.4 1.4', 'M17.7 17.7l1.4 1.4', 'M2 12h2', 'M20 12h2', 'M4.9 19.1l1.4-1.4', 'M17.7 6.3l1.4-1.4'];
const isNight = () => (document.documentElement.dataset.theme || (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light')) === 'dark';
function paintThemeButton() {
  const b = $('theme');
  b.replaceChildren(icon(isNight() ? SUN : MOON));
  b.setAttribute('aria-label', isNight() ? 'Switch to day theme' : 'Switch to night theme');
  b.setAttribute('aria-pressed', String(isNight()));
}
(function initTheme() {
  let t = null;
  try { t = localStorage.getItem(THEME_KEY); } catch { /* storage unavailable */ }
  if (t === 'light' || t === 'dark') document.documentElement.dataset.theme = t;
  paintThemeButton();
  $('theme').addEventListener('click', () => {
    const next = isNight() ? 'light' : 'dark';
    document.documentElement.dataset.theme = next;
    try { localStorage.setItem(THEME_KEY, next); } catch { /* storage unavailable */ }
    paintThemeButton();
    say(next === 'dark' ? 'Night theme' : 'Day theme');
  });
  matchMedia('(prefers-color-scheme: dark)').addEventListener('change', paintThemeButton);
}());

// ---------- boot ----------
$('signout').addEventListener('click', () => signOut());
window.addEventListener('hashchange', route);
route();
