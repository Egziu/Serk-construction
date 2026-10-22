// Browser end-to-end test of site operations (migration 0037) in the SERK
// console, started by internal/httpapi/console_browser_site_test.go (which
// verifies the outcome through the API afterwards). A site engineer registers
// a field device (step-up), records and submits a diary; the project manager
// approves it from the worklist; the engineer revokes the device.
// Accessibility is audited on every new page; phone width and dark theme too.
import { as, nav, act, selectByText, snap, audit, idFromHash, log, fail, failures, browser, pages } from './console_lib.mjs';

try {
  // ---- 1. Engineer registers a device (fresh MFA) -------------------------------------
  const eng = await as('eng');
  await nav(eng, '#/site/devices', 'Field devices');
  await audit(eng, 'field devices (empty)');
  await eng.getByLabel('Device name').fill('Tablet 9');
  await eng.getByRole('button', { name: 'Register a device' }).click();
  const secret = eng.locator('pre.secret');
  await secret.waitFor();
  if (!/device key sfd_/.test(await secret.textContent())) fail('the device key is not shown once after registration');
  await audit(eng, 'device registered');
  await snap(eng, 'device-registered');
  log('device registered; key shown once');

  // ---- 2. Engineer records and submits a diary --------------------------------------------
  await nav(eng, '#/new/diary', 'Record a site diary');
  await selectByText(eng.getByLabel('Project'), 'P-API');
  await eng.getByLabel('Weather').fill('Sunny, 27 C');
  await eng.getByLabel('Notes').fill('Blinding concrete grid A1-A4; crane inspection passed.');
  const lab = eng.getByRole('group', { name: /^Labour/ });
  await lab.getByLabel('Trade, line 1').fill('Masons');
  await lab.getByLabel('Headcount, line 1').fill('6');
  await lab.getByLabel('Person-hours, line 1').fill('48');
  await lab.getByRole('button', { name: 'Add line' }).click();
  await lab.getByLabel('Trade, line 2').fill('Steel fixers');
  await lab.getByLabel('Headcount, line 2').fill('4');
  await lab.getByLabel('Person-hours, line 2').fill('30.5');
  const eq = eng.getByRole('group', { name: /^Equipment/ });
  await eq.getByLabel('Equipment, line 1').fill('Mobile crane 50 t');
  await eq.getByLabel('Hours worked, line 1').fill('6');
  await eq.getByLabel('Hours idle, line 1').fill('2');
  await audit(eng, 'diary form');
  await eng.getByRole('button', { name: 'Save diary' }).click();
  await eng.getByRole('heading', { level: 1, name: /^Site diary SDY-/ }).waitFor();
  const dID = await idFromHash(eng);
  const view = await eng.locator('main').textContent();
  for (const v of ['Masons', 'Steel fixers', 'Mobile crane 50 t']) if (!view.includes(v)) fail(`the saved diary does not show ${v}`);
  await audit(eng, 'diary saved');
  await act(eng, 'Submit for approval', 'Submit for approval: done');
  if (await eng.getByRole('button', { name: 'Approve', exact: true }).count()) fail('the engineer is offered "Approve"');
  await snap(eng, 'diary-submitted');
  log('diary saved and submitted');

  // ---- 3. Project manager approves from the worklist -----------------------------------------
  const pm = await as('pm');
  await nav(pm, '#/home', 'My work');
  await pm.getByRole('link', { name: /Site diaries to approve/ }).waitFor();
  await nav(pm, `#/doc/site_diary/${dID}`, /^Site diary SDY-/);
  await act(pm, 'Approve', 'Approve: done');
  await pm.locator('main').filter({ hasText: 'APPROVED' }).waitFor();
  await audit(pm, 'diary approved');
  log('diary approved by the project manager');

  // ---- 4. Engineer revokes the device ----------------------------------------------------------
  await nav(eng, '#/site/devices', 'Field devices');
  await eng.getByLabel('Reason for revoking Tablet 9').fill('Tablet left on the bus');
  await eng.getByRole('button', { name: 'Revoke' }).click();
  await eng.getByRole('table', { name: /Devices/ }).filter({ hasText: 'REVOKED' }).waitFor();
  await audit(eng, 'device revoked');
  await snap(eng, 'device-revoked');
  log('device revoked');

  // ---- 5. Phone width, dark theme ---------------------------------------------------------------
  const phone = await as('pmPhone', { viewport: { width: 390, height: 844 }, colorScheme: 'dark' });
  await nav(phone, `#/doc/site_diary/${dID}`, /^Site diary SDY-/);
  await audit(phone, 'diary at 390px (dark)');
  await snap(phone, 'mobile-diary-dark');
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
console.log('\nCONSOLE SITE: PASS');
