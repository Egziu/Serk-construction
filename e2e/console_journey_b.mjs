// Browser end-to-end test of Journey B (contract to cash) in the SERK
// console: each person in their own browser context with their own token,
// against a real server and PostgreSQL. Started by
// internal/httpapi/console_browser_b_test.go, which seeds master data and the
// bank statement through the API and verifies the outcome independently
// through the API afterwards. Accessibility is audited on every new page.
import { as, nav, act, selectByText, snap, audit, h1, idFromHash, log, fail, failures, browser, pages, FX } from './console_lib.mjs';

try {
  // ---- 1. Contract: commercial manager records and submits -----------------------
  const com = await as('commercial');
  await nav(com, '#/new/contract', 'New client contract');
  await selectByText(com.getByLabel('Customer'), 'Ethiopian Roads');
  await com.getByLabel('Title').fill('Adama-Awash road section 2');
  await com.getByLabel('Client reference').fill('ERA/CW/2026/014');
  await com.getByLabel('Signed on').fill('2026-10-01');
  await com.getByLabel('Retention (fraction)').fill('0.05');
  await com.getByLabel('Advance amount').fill('1000000');
  await com.getByLabel('Advance recovery (fraction of each certificate)').fill('0.20');
  const lines = [['Bulk excavation', 'm3', '10000', '350'], ['Concrete C30', 'm3', '1200', '6500'], ['Reinforcement steel', 't', '120', '98000']];
  for (let i = 0; i < lines.length; i++) {
    if (i) await com.getByRole('button', { name: 'Add line' }).click();
    const n = i + 1;
    await com.getByLabel(`Description, line ${n}`).fill(lines[i][0]);
    await com.getByLabel(`Unit, line ${n}`).fill(lines[i][1]);
    await com.getByLabel(`Quantity, line ${n}`).fill(lines[i][2]);
    await com.getByLabel(`Rate, line ${n}`).fill(lines[i][3]);
  }
  await audit(com, 'contract form');
  await com.getByRole('button', { name: 'Create contract' }).click();
  await com.getByRole('heading', { level: 1, name: /^Contract CTR-/ }).waitFor();
  const contractID = await idFromHash(com);
  await act(com, 'Submit for approval', 'Submit for approval: done');
  log(`contract ${await h1(com)} submitted`);

  // ---- 2. CFO approves (MFA token) --------------------------------------------------
  const cfo = await as('cfo');
  await nav(cfo, '#/home', 'My work');
  await cfo.getByRole('link', { name: /Contracts to approve/ }).waitFor();
  await nav(cfo, `#/doc/contract/${contractID}`, /^Contract CTR-/);
  await act(cfo, 'Approve', 'Approve: done');
  await cfo.getByRole('heading', { level: 2, name: 'Commercial position' }).waitFor();
  await audit(cfo, 'active contract with position');
  await snap(cfo, 'contract-active');

  // Another project's quantity surveyor cannot open the contract.
  const otherQS = await as('otherQS');
  await nav(otherQS, `#/doc/contract/${contractID}`);
  await otherQS.locator('#alert').filter({ hasText: /not found/i }).waitFor();
  log('other-project QS: contract not found');

  // ---- 3. The advance arrives: AR clerk applies it, AR supervisor confirms -------------
  const clerk = await as('arClerk');
  const sup = await as('arSup');
  const receive = async (lineLabel, target, amount) => {
    await nav(clerk, '#/list/money_in/UNAPPLIED', 'Money received');
    await clerk.getByRole('link', { name: lineLabel }).click();
    await clerk.getByRole('heading', { level: 1, name: 'Record receipt' }).waitFor();
    await selectByText(clerk.getByLabel('Invoice or contract advance, line 1'), target);
    await clerk.getByLabel('Amount, line 1').fill(amount);
    await audit(clerk, `receipt form (${lineLabel})`);
    await clerk.getByRole('button', { name: 'Record receipt' }).click();
    await clerk.getByRole('heading', { level: 1, name: /^Receipt RCPT-/ }).waitFor();
    if (await clerk.getByRole('button', { name: 'Confirm receipt' }).count()) fail('the AR clerk who recorded a receipt is offered "Confirm receipt"');
    const id = await idFromHash(clerk);
    await nav(sup, `#/doc/customer_receipt/${id}`, /^Receipt RCPT-/);
    await act(sup, 'Confirm receipt', 'A draft journal was created');
  };
  await receive('CBE-B-001/1', 'Advance on CTR-', '1000000');
  log('advance received and confirmed');

  // ---- 4. Measurement: QS records, site engineer verifies ----------------------------
  const qs = await as('qs');
  await nav(qs, `#/doc/contract/${contractID}`, /^Contract CTR-/);
  await qs.getByRole('link', { name: 'Record measurement' }).click();
  await qs.getByRole('heading', { level: 1, name: 'Record measurement' }).waitFor();
  await qs.getByLabel('Measured quantity, line 1').waitFor();
  await qs.getByLabel('Period ending').fill('2026-10-15');
  for (const [n, q] of [[1, '4000'], [2, '300'], [3, '20']]) await qs.getByLabel(`Measured quantity, line ${n}`).fill(q);
  await audit(qs, 'measurement form');
  await qs.getByRole('button', { name: 'Create measurement' }).click();
  await qs.getByRole('heading', { level: 1, name: /^Measurement MS-/ }).waitFor();
  const msID = await idFromHash(qs);
  await act(qs, 'Submit for approval', 'Submit for approval: done');
  const se = await as('siteEng');
  await nav(se, `#/doc/measurement/${msID}`, /^Measurement MS-/);
  await act(se, 'Verify measurement', 'Verify measurement: done');
  log('measurement verified');

  // ---- 5. IPC: QS prepares, commercial manager certifies with the signed file ----------
  await nav(qs, `#/new/ipc/${contractID}`, 'Prepare payment certificate');
  await qs.getByLabel('Period ending').fill('2026-10-15');
  await audit(qs, 'IPC form');
  await qs.getByRole('button', { name: 'Prepare certificate' }).click();
  await qs.getByRole('heading', { level: 1, name: /^Payment certificate IPC-/ }).waitFor();
  const ipcID = await idFromHash(qs);
  await act(qs, 'Submit for approval', 'Submit for approval: done');
  await nav(com, `#/doc/ipc/${ipcID}`, /^Payment certificate IPC-/);
  const view = await com.locator('main').textContent();
  for (const v of ['5,310,000.00', '265,500.00', '1,000,000.00', '646,500.00', '4,691,000.00']) {
    if (!view.includes(v)) fail(`IPC page does not show ${v}`);
  }
  await com.getByLabel('Client certificate reference').fill('ERA-IPC-01');
  await com.getByLabel('Signed certificate file').setInputFiles({ name: 'ERA-IPC-01-signed.pdf', mimeType: 'application/pdf', buffer: Buffer.from('test') });
  await com.locator('output').filter({ hasText: 'SHA-256 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08' }).waitFor();
  await audit(com, 'IPC certification');
  await snap(com, 'ipc-certify');
  await act(com, 'Certify', 'Certify: done');
  log('IPC certified (SHA-256 of the signed file computed in the browser)');

  // ---- 6. Customer invoice: AR clerk issues, AR supervisor approves ---------------------
  await nav(clerk, `#/doc/ipc/${ipcID}`, /^Payment certificate IPC-/);
  await clerk.getByRole('button', { name: 'Issue customer invoice' }).click();
  await clerk.getByRole('heading', { level: 1, name: /^Customer invoice CINV-/ }).waitFor();
  const invID = await idFromHash(clerk);
  await nav(sup, `#/doc/customer_invoice/${invID}`, /^Customer invoice CINV-/);
  await act(sup, 'Approve', 'A draft journal was created');
  await audit(sup, 'approved customer invoice');
  await receive('CBE-B-001/2', 'Invoice CINV-', '4691000');
  log('invoice approved and paid in full');

  // ---- 7. Finance approves and posts the AR journals ------------------------------------
  const fin = await as('finMgr');
  const ctl = await as('controller');
  await nav(fin, '#/journals', 'Journals');
  await fin.getByLabel('Select all draft journals').check();
  await fin.getByRole('button', { name: 'Approve selected' }).click();
  await fin.locator('p.notice').filter({ hasText: '3 of 3 journals done' }).waitFor();
  await nav(ctl, '#/journals', 'Journals');
  await ctl.getByLabel('Select all approved journals').check();
  await ctl.getByRole('button', { name: 'Post selected' }).click();
  await ctl.locator('p.notice').filter({ hasText: '3 of 3 journals done' }).waitFor();
  log('3 AR journals approved and posted');

  // ---- 8. Reconciliation and position ------------------------------------------------------
  await nav(ctl, '#/recon', 'Reconciliation');
  await ctl.getByRole('table', { name: /Receivables to general ledger/ }).waitFor();
  if (await ctl.locator('tr.diff').count()) fail('reconciliation shows differences');
  if (await ctl.locator('p.alert').count()) fail(`reconciliation alert: ${await ctl.locator('p.alert').first().textContent()}`);
  await audit(ctl, 'reconciliation with receivables');
  await snap(ctl, 'reconciliation-receivables');
  const dark = await as('controllerDark', { colorScheme: 'dark' });
  await nav(dark, '#/recon', 'Reconciliation');
  await dark.getByRole('table', { name: /Receivables to general ledger/ }).waitFor();
  await audit(dark, 'reconciliation with receivables (dark theme)');
  await nav(com, `#/doc/contract/${contractID}`, /^Contract CTR-/);
  const policyHref = await com.getByRole('link', { name: 'Open contract policy' }).getAttribute('href');
  if (!policyHref || !policyHref.startsWith('#/doc/contract_policy/')) fail(`contract policy link points to ${policyHref}`);
  const pos = await com.locator('.panel').filter({ hasText: 'Commercial position' }).textContent();
  for (const v of ['23,060,000.00', '5,310,000.00', '265,500.00', '4,691,000.00']) {
    if (!pos.includes(v)) fail(`contract position does not show ${v}`);
  }
  await snap(com, 'contract-position');

  // ---- 9. Phone width ------------------------------------------------------------------------
  const phone = await as('commercialPhone', { viewport: { width: 390, height: 844 } });
  await nav(phone, `#/doc/ipc/${ipcID}`, /^Payment certificate IPC-/);
  await audit(phone, 'IPC at 390px');
  await nav(phone, `#/doc/contract/${contractID}`, /^Contract CTR-/);
  await audit(phone, 'contract at 390px');
  await snap(phone, 'mobile-contract');
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
console.log(`\nCONSOLE JOURNEY B: PASS (${FX.project})`);
