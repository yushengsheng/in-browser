'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const root = path.resolve(__dirname, '..');
const productionPath = path.join(root, 'app/fingerprint_continuity.py');
const sourceBytes = fs.readFileSync(productionPath);
const hash = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const sourceHash = hash(sourceBytes);
const source = sourceBytes.toString('utf8').replace(/\r\n/g, '\n');
const expression = source.match(/_EXPRESSION = r"""([\s\S]*?)"""/)[1];
const prelude = expression.slice(expression.indexOf('  const values ='), expression.indexOf('  const sync ='));
// Explicit regression fixture: the deadline formerly started before fn's microtask.
const original = String.raw`  const bounded = async (key, fn, limit=1000) => {
    let timer;
    try {
      const value = await Promise.race([Promise.resolve().then(fn),
        new Promise((_, reject) => { timer=setTimeout(() => reject(new Error()), limit); })]);
      put(key, value);
    } catch (_) { errors.push(key); }
    finally { clearTimeout(timer); }
  };`;
const candidate = expression.slice(expression.indexOf('  const bounded ='), expression.indexOf('  const bytes ='));
const devicesSection = expression.slice(expression.indexOf('  if (navigator.mediaDevices'), expression.indexOf('  await Promise.all(jobs)'));

// Native promise microtasks run, but no wall-clock timer or sleep is used.
async function drainMicrotasks() {
  for (let index = 0; index < 24; index++) await Promise.resolve();
}

class FakeClock {
  constructor() {
    this.now = 0;
    this.nextId = 1;
    this.timers = new Map();
    this.registered = [];
    this.cleared = [];
  }

  schedule(callback, delay, kind) {
    const timer = { id: this.nextId++, due: this.now + delay, callback, kind };
    this.timers.set(timer.id, timer);
    this.registered.push({ id: timer.id, due: timer.due, started: this.now, kind });
    return timer.id;
  }

  clear(id) {
    this.cleared.push(id);
    this.timers.delete(id);
  }

  synchronousWork(milliseconds) {
    this.now += milliseconds;
  }

  async advance(milliseconds) {
    const target = this.now + milliseconds;
    while (true) {
      const next = [...this.timers.values()]
        .filter(timer => timer.due <= target)
        .sort((a, b) => a.due - b.due || a.id - b.id)[0];
      if (!next) break;
      this.now = Math.max(this.now, next.due);
      this.timers.delete(next.id);
      next.callback();
      await drainMicrotasks();
    }
    this.now = target;
    await drainMicrotasks();
  }

  assertDeadlinesReleased(expectedCount) {
    const deadlines = this.registered.filter(timer => timer.kind === 'deadline');
    assert.equal(deadlines.length, expectedCount);
    for (const timer of deadlines) assert(this.cleared.includes(timer.id));
    assert.equal([...this.timers.values()].filter(timer => timer.kind === 'deadline').length, 0);
  }
}

function loadHelper(helper) {
  const clock = new FakeClock();
  const sandbox = {
    setTimeout: (callback, delay) => clock.schedule(callback, delay, 'deadline'),
    clearTimeout: id => clock.clear(id),
  };
  const api = vm.runInNewContext(`(() => {
${prelude}
${helper}
return { bounded, sampleDevices: () => {
  const jobs = [];
${devicesSection}
  return Promise.all(jobs);
}, snapshot: () => JSON.stringify({ values, errors }) };
})()`, sandbox);
  return { clock, bounded: api.bounded, sampleDevices: api.sampleDevices,
    setNavigator: navigator => { sandbox.navigator = navigator; },
    snapshot: () => JSON.parse(api.snapshot()) };
}

function finishable(promise) {
  const task = { done: false };
  task.promise = promise.then(() => { task.done = true; });
  return task;
}

function delayed(clock, milliseconds, value, reject = false) {
  return new Promise((resolve, fail) => clock.schedule(
    () => reject ? fail(new Error('synthetic-rejection')) : resolve(value), milliseconds, 'api'));
}

async function delayedStart(helper) {
  const fixture = loadHelper(helper);
  const starts = [];
  const task = finishable(fixture.bounded('uaData.high', () => {
    starts.push(fixture.clock.now);
    return delayed(fixture.clock, 20, { architecture: 'synthetic-architecture' });
  }));
  fixture.clock.synchronousWork(1500);
  await drainMicrotasks();
  await fixture.clock.advance(0);
  await fixture.clock.advance(20);
  assert(task.done);
  await task.promise;
  assert.deepEqual(starts, [1500]);
  fixture.clock.assertDeadlinesReleased(1);
  return { snapshot: fixture.snapshot(), deadline: fixture.clock.registered.find(timer => timer.kind === 'deadline') };
}

async function timeoutStillFails(helper, field = 'audio.offline') {
  const fixture = loadHelper(helper);
  const task = finishable(fixture.bounded(field, () => delayed(fixture.clock, 1100, 'synthetic-value')));
  await drainMicrotasks();
  await fixture.clock.advance(1000);
  assert(task.done);
  await task.promise;
  assert.deepEqual(fixture.snapshot(), { values: {}, errors: [field] });
  fixture.clock.assertDeadlinesReleased(1);
  await fixture.clock.advance(100);
  assert.deepEqual(fixture.snapshot(), { values: {}, errors: [field] });
}

async function productionDevicesBudget(milliseconds, shouldPass) {
  const fixture = loadHelper(candidate);
  const kinds = { audioinput: 1, audiooutput: 1, videoinput: 0 };
  fixture.setNavigator({ mediaDevices: { enumerateDevices: () => delayed(fixture.clock, milliseconds,
    [{ kind: 'audioinput' }, { kind: 'audiooutput' }]) } });
  const task = finishable(fixture.sampleDevices());
  await drainMicrotasks();
  const deadline = fixture.clock.registered.find(timer => timer.kind === 'deadline');
  assert.equal(deadline.due - deadline.started, 3000);
  await fixture.clock.advance(Math.min(milliseconds, 3000));
  assert(task.done);
  await task.promise;
  const expected = shouldPass
    ? { values: { 'devices.supported': true, 'devices.kinds': kinds }, errors: [] }
    : { values: { 'devices.supported': true }, errors: ['devices.kinds'] };
  assert.deepEqual(fixture.snapshot(), expected);
  fixture.clock.assertDeadlinesReleased(1);
  if (milliseconds > 3000) {
    await fixture.clock.advance(milliseconds - 3000);
    assert.deepEqual(fixture.snapshot(), expected);
  }
}

async function rejectionStillFails(helper, synchronous) {
  const fixture = loadHelper(helper);
  const task = finishable(fixture.bounded('uaData.high', () => {
    if (synchronous) throw new Error('synthetic-throw');
    return delayed(fixture.clock, 20, null, true);
  }));
  await drainMicrotasks();
  await fixture.clock.advance(20);
  assert(task.done);
  await task.promise;
  assert.deepEqual(fixture.snapshot(), { values: {}, errors: ['uaData.high'] });
  fixture.clock.assertDeadlinesReleased(1);
}

async function neverSettlingStillFails(helper) {
  const fixture = loadHelper(helper);
  const task = finishable(fixture.bounded('devices.kinds', () => new Promise(() => {})));
  await drainMicrotasks();
  await fixture.clock.advance(1000);
  assert(task.done);
  await task.promise;
  assert.deepEqual(fixture.snapshot(), { values: {}, errors: ['devices.kinds'] });
  fixture.clock.assertDeadlinesReleased(1);
}

async function completeSample(helper, syncMilliseconds) {
  const fixture = loadHelper(helper);
  const entries = [
    ['uaData.high', { architecture: 'synthetic', bitness: '64' }, 20],
    ['audio.offline', 'base64:c3ludGhldGlj', 30],
    ['devices.kinds', { audioinput: 1, audiooutput: 1, videoinput: 0 }, 40],
  ];
  const tasks = entries.map(([key, value, milliseconds]) => finishable(
    fixture.bounded(key, () => delayed(fixture.clock, milliseconds, value))));
  fixture.clock.synchronousWork(syncMilliseconds);
  await drainMicrotasks();
  await fixture.clock.advance(40);
  for (const task of tasks) {
    assert(task.done);
    await task.promise;
  }
  fixture.clock.assertDeadlinesReleased(3);
  return fixture.snapshot();
}

async function main() {
  const checks = [];
  const oldStart = await delayedStart(original);
  assert.deepEqual(oldStart.snapshot, { values: {}, errors: ['uaData.high'] });
  assert.equal(oldStart.deadline.started, 0);
  assert.equal(oldStart.deadline.due, 1000);
  checks.push('original_1500ms_sync_then_20ms_api_fails');

  const newStart = await delayedStart(candidate);
  assert.deepEqual(newStart.snapshot, { values: { 'uaData.high': { architecture: 'synthetic-architecture' } }, errors: [] });
  assert.equal(newStart.deadline.started, 1500);
  assert.equal(newStart.deadline.due, 2500);
  checks.push('candidate_starts_api_and_1000ms_budget_together');

  for (const [name, helper] of [['original', original], ['candidate', candidate]]) {
    await timeoutStillFails(helper);
    checks.push(name + '_late_result_still_fails_and_cannot_fill_value');
    await rejectionStillFails(helper, false);
    checks.push(name + '_api_rejection_still_fails');
    await rejectionStillFails(helper, true);
    checks.push(name + '_synchronous_throw_still_fails');
    await neverSettlingStillFails(helper);
    checks.push(name + '_never_settling_api_still_fails');
  }

  const originalFast = await completeSample(original, 0);
  const candidateFirst = await completeSample(candidate, 1500);
  const candidateSecond = await completeSample(candidate, 1500);
  assert.equal(Object.keys(originalFast.values).length, 3);
  assert.deepEqual(originalFast.errors, []);
  assert.deepEqual(candidateFirst, originalFast);
  assert.deepEqual(candidateSecond, originalFast);
  checks.push('candidate_both_reads_keep_all_three_original_values');

  await productionDevicesBudget(1500, true);
  checks.push('production_devices_1500ms_enumeration_passes');
  await productionDevicesBudget(2999, true);
  checks.push('production_devices_2999ms_enumeration_passes');
  await productionDevicesBudget(3001, false);
  checks.push('production_devices_after_3000ms_fails_without_late_value');
  checks.push('production_devices_call_uses_3000ms_budget');
  await timeoutStillFails(candidate, 'uaData.high');
  checks.push('candidate_ua_after_1000ms_still_fails');

  assert.equal(hash(fs.readFileSync(productionPath)), sourceHash);
  checks.push('production_source_unchanged');
  const result = {
    success: true,
    runtime: process.version,
    fake_clock_only: true,
    default_limit_ms: 1000,
    devices_limit_ms: 3000,
    production_source_sha256: sourceHash,
    checks: Object.fromEntries(checks.map(name => [name, true])),
    check_count: checks.length,
    limitations: ['Deterministic helper test; does not establish the live batch failure cause.',
      'No real waits, browser, or network; comparison and authentication are outside this helper test.'],
  };
  process.stdout.write(JSON.stringify(result) + '\n');
}

main().catch(error => {
  process.stderr.write(error.stack + '\n');
  process.exitCode = 1;
});
