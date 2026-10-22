// Browser end-to-end test of Journey C (stock valuation) in the SERK console,
// started by internal/httpapi/console_browser_c_test.go (which seeds a
// confirmed goods receipt posted to inventory and verifies the outcome
// through the API afterwards). Every stock step is done in the UI by the
// person who would do it; accessibility is audited on every new page.
import { as, nav, act, selectByText, snap, audit, idFromHash, log, fail, failures, browser, pages, FX } from './console_lib.mjs';

try {
  // ---- 1. Stock item: procurement officer creates, finance manager approves -----
  const buyer = await as('buyer');
  await nav(buyer, '#/new/stockitem', 'New stock item');
  await buyer.getByLabel('Item code').fill('STEEL-G60');
  await buyer.getByLabel('Name').fill('Reinforcement steel Grade 60');
  await buyer.getByLabel('Unit').fill('t');
  await buyer.getByLabel('Valuation').selectOption('FIFO');
  await selectByText(buyer.getByLabel('Inventory account'), '1200');
  await audit(buyer, 'stock item form');
  await buyer.getByRole('button', { name: 'Create stock item' }).click();
  await buyer.getByRole('heading', { level: 1, name: /^Stock item STEEL-G60/ }).waitFor();
  const itemID = await idFromHash(buyer);
  const fin = await as('finMgr');
  await nav(fin, `#/doc/stock_item/${itemID}`, /^Stock item/);
  await act(fin, 'Approve', 'Approve: done');

  // ---- 1b. Procurement names the stock item of the PO line (R8-F8) ---------------------
  await nav(buyer, `#/doc/grn/${FX.grn}`, /^Goods receipt/);
  await buyer.getByRole('link', { name: 'Open purchase order' }).click();
  await buyer.getByRole('heading', { level: 1, name: /^Purchase order/ }).waitFor();
  await buyer.getByRole('link', { name: 'Designate stock items' }).click();
  await buyer.getByRole('heading', { level: 1, name: 'Designate stock items' }).waitFor();
  await selectByText(buyer.getByLabel('Purchase order line'), 'Reinforcement steel');
  await selectByText(buyer.getByLabel('Stock item'), 'STEEL-G60');
  await audit(buyer, 'designate stock item form');
  await buyer.getByRole('button', { name: 'Designate' }).click();
  await buyer.getByRole('heading', { level: 1, name: /^Purchase order/ }).waitFor();
  log('PO line 1 designated as STEEL-G60 by procurement');

  // ---- 2. Warehouse: procurement manager creates the project store -----------------
  const pmgr = await as('procMgr');
  await nav(pmgr, '#/new/warehouse', 'New warehouse');
  await selectByText(pmgr.getByLabel('Project'), 'P-API');
  await pmgr.getByLabel('Code').fill('P-STORE');
  await pmgr.getByLabel('Name').fill('Project site store');
  await audit(pmgr, 'warehouse form');
  await pmgr.getByRole('button', { name: 'Create warehouse' }).click();
  await pmgr.getByRole('heading', { level: 1, name: /^Warehouse P-STORE/ }).waitFor();

  // ---- 3. Put-away: storekeeper, from the confirmed goods receipt -------------------
  const store = await as('store');
  await nav(store, `#/doc/grn/${FX.grn}`, /^Goods receipt/);
  await store.getByRole('link', { name: 'Put away into a warehouse' }).click();
  await store.getByRole('heading', { level: 1, name: 'Put away into a warehouse' }).waitFor();
  await store.getByLabel('Purchase order line').fill('1');
  await selectByText(store.getByLabel('Stock item'), 'STEEL-G60');
  await selectByText(store.getByLabel('Warehouse'), 'P-STORE');
  await store.getByLabel('Quantity').fill('12');
  await audit(store, 'put-away form');
  await store.getByRole('button', { name: 'Put away' }).click();
  await store.getByRole('heading', { level: 1, name: 'Stock on hand' }).waitFor();
  await store.getByRole('row').filter({ hasText: 'STEEL-G60' }).filter({ hasText: '1,014,000.00' }).waitFor();
  await audit(store, 'stock on hand');
  await snap(store, 'stock-on-hand');
  log('12 t put away at 84,500 (1,014,000)');

  // ---- 4. Issue: storekeeper requests, site engineer approves -----------------------
  await store.getByRole('link', { name: 'Issue stock' }).click();
  await store.getByRole('heading', { level: 1, name: 'Issue stock to a project' }).waitFor();
  await selectByText(store.getByLabel('Warehouse'), 'P-STORE');
  await selectByText(store.getByLabel('Stock item'), 'STEEL-G60');
  await store.getByLabel('Quantity').fill('5');
  await selectByText(store.getByLabel('Cost code'), '01-MAT');
  await selectByText(store.getByLabel('Expense account'), '5000');
  await audit(store, 'stock issue form');
  await store.getByRole('button', { name: 'Request issue' }).click();
  await store.getByRole('heading', { level: 1, name: /^Stock issue SIS-/ }).waitFor();
  if (await store.getByRole('button', { name: 'Approve', exact: true }).count()) fail('the storekeeper who requested an issue is offered "Approve"');
  const issueID = await idFromHash(store);
  const se = await as('siteEng');
  await nav(se, `#/doc/stock_issue/${issueID}`, /^Stock issue/);
  await act(se, 'Approve', 'A draft journal was created');
  const issueView = await se.locator('main').textContent();
  if (!issueView.includes('422,500.00')) fail('the approved issue does not show its FIFO cost 422,500.00');
  await audit(se, 'approved stock issue');
  await snap(se, 'stock-issue-approved');

  // ---- 5. Count: storekeeper records 6.5 t (book 7), inventory controller approves -------
  await nav(store, '#/new/stockcount', 'Record a stock count');
  await selectByText(store.getByLabel('Warehouse'), 'P-STORE');
  await selectByText(store.getByLabel('Stock item'), 'STEEL-G60');
  await store.getByLabel('Counted quantity').fill('6.5');
  await selectByText(store.getByLabel('Variance account'), '5200');
  await audit(store, 'stock count form');
  await store.getByRole('button', { name: 'Record count' }).click();
  await store.getByRole('heading', { level: 1, name: /^Stock count SCT-/ }).waitFor();
  const countID = await idFromHash(store);
  const ic = await as('invCtl');
  await nav(ic, `#/doc/stock_count/${countID}`, /^Stock count/);
  await act(ic, 'Approve', 'A draft journal was created');
  log('issue (422,500) and shortage (42,250) approved');

  // ---- 5b. Transfer 1 t to a second store: storekeeper requests, inventory controller approves
  await nav(pmgr, '#/new/warehouse', 'New warehouse');
  await selectByText(pmgr.getByLabel('Project'), 'P-API');
  await pmgr.getByLabel('Code').fill('P-STORE-B');
  await pmgr.getByLabel('Name').fill('Second site store');
  await pmgr.getByRole('button', { name: 'Create warehouse' }).click();
  await pmgr.getByRole('heading', { level: 1, name: /^Warehouse P-STORE-B/ }).waitFor();
  await nav(store, '#/new/stocktransfer', 'Transfer stock');
  await selectByText(store.getByLabel('From warehouse'), 'P-STORE ');
  await selectByText(store.getByLabel('To warehouse'), 'P-STORE-B');
  await selectByText(store.getByLabel('Stock item'), 'STEEL-G60');
  await store.getByLabel('Quantity').fill('1');
  await audit(store, 'stock transfer form');
  await store.getByRole('button', { name: 'Request transfer' }).click();
  await store.getByRole('heading', { level: 1, name: /^Stock transfer STR-/ }).waitFor();
  if (await store.getByRole('button', { name: 'Approve', exact: true }).count()) fail('the storekeeper who requested a transfer is offered "Approve"');
  const trID = await idFromHash(store);
  await nav(ic, `#/doc/stock_transfer/${trID}`, /^Stock transfer/);
  await act(ic, 'Approve', 'Approve: done');
  const trView = await ic.locator('main').textContent();
  if (!trView.includes('84,500.00')) fail('the approved transfer does not show its FIFO cost 84,500.00');
  await audit(ic, 'approved stock transfer');
  await snap(ic, 'stock-transfer-approved');
  log('1 t transferred to the second store at 84,500 (no journal)');

  // ---- 6. Finance approves and posts; reconciliation -------------------------------------
  const ctl = await as('controller');
  await nav(fin, '#/journals', 'Journals');
  await fin.getByLabel('Select all draft journals').check();
  await fin.getByRole('button', { name: 'Approve selected' }).click();
  await fin.locator('p.notice').filter({ hasText: '2 of 2 journals done' }).waitFor();
  await nav(ctl, '#/journals', 'Journals');
  await ctl.getByLabel('Select all approved journals').check();
  await ctl.getByRole('button', { name: 'Post selected' }).click();
  await ctl.locator('p.notice').filter({ hasText: '2 of 2 journals done' }).waitFor();
  await nav(ctl, '#/recon', 'Reconciliation');
  await ctl.getByRole('table', { name: /Inventory to general ledger/ }).waitFor();
  if (await ctl.locator('tr.diff').count()) fail('reconciliation shows differences');
  if (await ctl.locator('p.alert').count()) fail(`reconciliation alert: ${await ctl.locator('p.alert').first().textContent()}`);
  await ctl.getByRole('row').filter({ hasText: 'Inventory: 1200' }).filter({ hasText: '831,250.00' }).waitFor();
  await audit(ctl, 'reconciliation with inventory');
  await snap(ctl, 'reconciliation-inventory');

  // ---- 7. Phone width and dark theme ------------------------------------------------------
  const phone = await as('storePhone', { viewport: { width: 390, height: 844 }, colorScheme: 'dark' });
  await nav(phone, '#/stock', 'Stock on hand');
  await phone.getByRole('row').filter({ hasText: 'STEEL-G60' }).first().waitFor();
  await audit(phone, 'stock on hand at 390px (dark)');
  await snap(phone, 'mobile-stock-dark');
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
console.log('\nCONSOLE JOURNEY C: PASS');
