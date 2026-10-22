// Browser end-to-end test of planning (migration 0027) in the SERK console,
// started by internal/httpapi/console_browser_planning_test.go (which seeds an
// approved BOQ and verifies earned value through the API afterwards). The
// planner builds the textbook network (docs/testing/E2E_PLANNING.md) in the
// schedule form; accessibility is audited on every new page.
import { as, nav, act, selectByText, snap, audit, idFromHash, log, fail, failures, browser, pages } from './console_lib.mjs';

try {
  // ---- 1. Planner builds the schedule -------------------------------------------------
  const planner = await as('planner');
  await nav(planner, '#/new/schedule', 'New schedule');
  await selectByText(planner.getByLabel('Project'), 'P-API');
  await planner.getByLabel('Description').fill('Tender programme rev A');
  await planner.getByLabel('Start date').fill('2026-10-05');
  const actsGrid = planner.getByRole('group', { name: 'Activities' });
  await actsGrid.getByLabel('Code, line 1', { exact: true }).waitFor();
  const acts = [['A', 'Mobilisation', '3', '1000000'], ['B', 'Excavation', '4', '2000000'], ['C', 'Drainage', '2', '500000'],
    ['D', 'Foundations', '5', '3000000'], ['E', 'Handover', '1', '']];
  for (let i = 0; i < acts.length; i++) {
    if (i > 0) await actsGrid.getByRole('button', { name: 'Add line' }).click();
    const n = i + 1;
    const [code, name, dur, budget] = acts[i];
    await actsGrid.getByLabel(`Code, line ${n}`, { exact: true }).fill(code);
    await actsGrid.getByLabel(`Name, line ${n}`, { exact: true }).fill(name);
    await actsGrid.getByLabel(`Duration (working days), line ${n}`).fill(dur);
    if (budget) {
      await selectByText(actsGrid.getByLabel(`Cost code, line ${n}`), '01-MAT');
      await actsGrid.getByLabel(`Budget, line ${n}`).fill(budget);
    }
  }
  const deps = planner.getByRole('group', { name: 'Dependencies' });
  const links = [['A', 'B'], ['A', 'C'], ['B', 'D'], ['C', 'E'], ['D', 'E']];
  for (let i = 0; i < links.length; i++) {
    if (i > 0) await deps.getByRole('button', { name: 'Add line' }).click();
    await deps.getByLabel(`Predecessor, line ${i + 1}`).fill(links[i][0]);
    await deps.getByLabel(`Successor, line ${i + 1}`).fill(links[i][1]);
  }
  await audit(planner, 'schedule form');
  await planner.getByRole('button', { name: 'Compute and save' }).click();
  await planner.getByRole('heading', { level: 1, name: /^Schedule v1/ }).waitFor();
  const view = await planner.locator('main').textContent();
  if (!view.includes('2026-10-19')) fail('the computed schedule does not show the finish 2026-10-19');
  await audit(planner, 'computed schedule');
  await snap(planner, 'schedule-computed');
  const vID = await idFromHash(planner);
  await act(planner, 'Submit for approval', 'Submit for approval: done');
  if (await planner.getByRole('button', { name: 'Approve', exact: true }).count()) fail('the planner is offered "Approve"');
  log('schedule computed (finish 2026-10-19) and submitted');

  // ---- 2. Project manager approves the baseline -------------------------------------------
  const pm = await as('pm');
  await nav(pm, '#/home', 'My work');
  await pm.getByRole('link', { name: /Schedules to approve/ }).waitFor();
  await nav(pm, `#/doc/schedule_version/${vID}`, /^Schedule v1/);
  await act(pm, 'Approve', 'Approve: done');
  await pm.locator('main').filter({ hasText: 'BASELINE' }).waitFor();
  log('baseline approved');

  // ---- 3. Planner reports progress at 2026-10-14; project manager approves -----------------
  await nav(planner, '#/new/progress', 'Report progress');
  await selectByText(planner.getByLabel('Project'), 'P-API');
  await planner.getByLabel('Status date').fill('2026-10-14');
  const pg = planner.getByRole('group', { name: /Progress by activity/ });
  await pg.getByLabel('Percent complete, line 1').waitFor();
  const prog = [['100', '2026-10-05', '2026-10-07'], ['100', '2026-10-08', '2026-10-13'], ['50', '2026-10-08', ''], ['20', '2026-10-14', '']];
  for (let i = 0; i < prog.length; i++) {
    const n = i + 1;
    await pg.getByLabel(`Percent complete, line ${n}`).fill(prog[i][0]);
    await pg.getByLabel(`Actual start, line ${n}`).fill(prog[i][1]);
    if (prog[i][2]) await pg.getByLabel(`Actual finish, line ${n}`).fill(prog[i][2]);
  }
  await audit(planner, 'progress form');
  await planner.getByRole('button', { name: 'Record progress' }).click();
  await planner.getByRole('heading', { level: 1, name: /^Progress report PRG-/ }).waitFor();
  const prID = await idFromHash(planner);
  await nav(pm, `#/doc/schedule_progress/${prID}`, /^Progress report PRG-/);
  await act(pm, 'Approve', 'Approve: done');
  log('progress at 2026-10-14 approved');

  // ---- 4. Earned value ---------------------------------------------------------------------------
  await nav(pm, '#/evm', 'Earned value');
  await selectByText(pm.getByLabel('Project'), 'P-API');
  await pm.getByLabel('Status date').fill('2026-10-14');
  await pm.getByLabel('Status date').dispatchEvent('change');
  const evm = pm.getByRole('table', { name: /Earned value at 2026-10-14/ });
  await evm.waitFor();
  if (await evm.count() !== 1) fail(`${await evm.count()} earned value tables are shown`);
  const text = await evm.textContent();
  for (const v of ['6,500,000.00', '4,700,000.00', '3,850,000.00', '\u2212850,000.00', '0.8191']) {
    if (!text.includes(v)) fail(`the earned value table does not show ${v}`);
  }
  await audit(pm, 'earned value');
  await snap(pm, 'earned-value');

  // ---- 5. Phone width, dark theme --------------------------------------------------------------
  const phone = await as('pmPhone', { viewport: { width: 390, height: 844 }, colorScheme: 'dark' });
  await nav(phone, `#/doc/schedule_version/${vID}`, /^Schedule v1/);
  await audit(phone, 'schedule at 390px (dark)');
  await snap(phone, 'mobile-schedule-dark');
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
console.log('\nCONSOLE PLANNING: PASS');
