// Pure control-flow tests. No exploit primitives, native code, or PS5 calls run.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');
const web = path.resolve(__dirname, '../web');

function node() {
  return { disabled: true, checked: false, hidden: true, textContent: '', className: '',
    classList: { add() {}, toggle() {} }, listeners: {},
    addEventListener(type, listener) { this.listeners[type] = listener; } };
}

function launcher(runRelapse, dumpMode = false) {
  const nodes = Object.fromEntries(['start-relapse', 'firmware-status', 'console', 'dump-mode'].map(id => [id, node()]));
  nodes['dump-mode'].checked = dumpMode;
  const messages = [];
  const window = { location: { search: '' }, firmware: { rejection: () => null }, fw_str: '13.60',
    __relapseOffsetsReady: Promise.resolve(),
    __relapseDiagnostics: { sessionId: 'new-run', log(message) { messages.push(message); return true; }, drain: async () => true } };
  const context = vm.createContext({ document: { getElementById: id => nodes[id] }, window,
    loadSite: async () => ({ runRelapse: () => runRelapse(window) }) });
  const source = fs.readFileSync(path.join(web, 'relapse/launch.js'), 'utf8')
    .replace('await import("./src/site.js")', 'await globalThis.loadSite()');
  vm.runInContext(source, context);
  return { nodes, messages, window };
}

test('upstream firmware inputs are required and failed checks stay actionable', async () => {
  const { nodes, window } = launcher(async () => ({ done: true, payloads: true }));
  window.firmware = null;
  await nodes['start-relapse'].listeners.click();
  assert.match(nodes['firmware-status'].textContent, /firmware check did not load/);
  assert.equal(nodes['start-relapse'].disabled, false);
});

test('Relapse page completes without claiming HV readiness', async () => {
  let finish;
  const { nodes, messages } = launcher(() => new Promise(resolve => { finish = resolve; }));
  const running = nodes['start-relapse'].listeners.click();
  await new Promise(setImmediate);
  assert.equal(messages.includes('Relapse cleanup complete; HV delivery ready.'), false);
  finish({ done: true, payloads: true });
  await running;
  assert.equal(messages.includes('Relapse cleanup complete; HV delivery ready.'), true);
  assert.match(nodes['firmware-status'].textContent, /does not confirm a hypervisor bypass/);
});

test('cleanup warning or failed loader cannot publish HV readiness', async () => {
  for (const cleanupWarning of [false, true]) {
    const { nodes, messages } = launcher(async window => {
      window.__relapseCleanupFailed = cleanupWarning;
      return { payloads: cleanupWarning };
    });
    await nodes['start-relapse'].listeners.click();
    assert.equal(nodes['start-relapse'].disabled, true);
    assert.equal(messages.includes('Relapse cleanup complete; HV delivery ready.'), false);
  }
});

test('single Relapse launcher reads dump choice before starting', async () => {
  for (const [checked, expected] of [[false, 'relapse'], [true, 'dump']]) {
    let finish;
    const { nodes, window } = launcher(() => new Promise(resolve => { finish = resolve; }), checked);
    const running = nodes['start-relapse'].listeners.click();
    await new Promise(setImmediate);
    assert.equal(window.__relapseMode, expected);
    finish({ done: true, payloads: true });
    await running;
    assert.equal(nodes['dump-mode'].disabled, true);
  }
});

test('normal HV run returns through cleanup instead of waiting for extraction', async () => {
  let source = fs.readFileSync(path.join(web, 'relapse/src/relapse_exploit.js'), 'utf8');
  source = source.replace(/^import .*;\r?\n/gm, '').replace('export async function', 'async function');
  const context = vm.createContext({ window: { __relapseMode: 'hv' }, setTimeout });
  vm.runInContext(source + '\nglobalThis.KernelExploit = KernelExploit;', context);
  const instance = Object.create(context.KernelExploit.prototype);
  const calls = [];
  instance.report = () => {};
  for (const name of ['leakKernelBase', 'pinToSingleCore', 'armKernelReadWrite', 'findCurrentProcess',
                      'locatePipes', 'crossPipes', 'defuseAioGroups', 'escalate', 'launchShellcode', 'rescue']) {
    instance[name] = async () => { calls.push(name); return true; };
  }
  instance.kbase = { toString: () => 'test' };
  const result = await instance.run();
  assert.equal(result.payloads, true);
  assert.equal(calls.at(-1), 'rescue');
  assert.ok(calls.indexOf('rescue') > calls.indexOf('launchShellcode'));
});

test('opt-in extraction still defers cleanup until Finish & restore', async () => {
  let source = fs.readFileSync(path.join(web, 'relapse/src/relapse_exploit.js'), 'utf8');
  source = source.replace(/^import .*;\r?\n/gm, '').replace('export async function', 'async function')
    .replace('await import("../extract_fw1360.js")', 'await globalThis.loadExtraction()');
  let finish;
  const context = vm.createContext({ window: { __relapseMode: 'dump' }, setTimeout,
    loadExtraction: async () => ({ runFw1360Extraction: () => new Promise(resolve => { finish = resolve; }) }) });
  vm.runInContext(source + '\nglobalThis.KernelExploit = KernelExploit;', context);
  const instance = Object.create(context.KernelExploit.prototype);
  let cleaned = false;
  instance.report = () => {};
  for (const name of ['leakKernelBase', 'pinToSingleCore', 'armKernelReadWrite', 'findCurrentProcess',
                      'locatePipes', 'crossPipes', 'defuseAioGroups', 'escalate', 'launchShellcode']) {
    instance[name] = async () => true;
  }
  instance.rescue = async () => { cleaned = true; };
  instance.kbase = { toString: () => 'test' };
  const running = instance.run();
  await new Promise(setImmediate);
  assert.equal(cleaned, false);
  finish();
  await running;
  assert.equal(cleaned, true);
});

async function hvPage({ state = 'ready', responseFails = false, handoff = 'same-run' } = {}) {
  const nodes = Object.fromEntries(['status', 'loader-ready', 'send-payload', 'send-result', 'hv-confirmed'].map(id => [id, node()]));
  const calls = [];
  const context = vm.createContext({
    document: { getElementById: id => nodes[id] },
    navigator: { userAgent: 'Mozilla/5.0 (PlayStation; PlayStation 5/13.60)' },
    window: { location: { search: handoff ? '?relapse_session_id=' + handoff : '' } },
    URLSearchParams,
    fetch: async (url, options = {}) => {
      calls.push({ url, options });
      if (options.method === 'POST') {
        if (responseFails) throw Error('HTTP response lost after sending');
        return { ok: true, json: async () => ({ sent: true, bytes_sent: 177256, message: 'Sent' }) };
      }
      return { ok: true, json: async () => ({ eligible: true, firmware: '13.60', payload_bytes: 177256,
        relapse_ready: state === 'ready', relapse_session_id: 'same-run',
        transfer_state: state === 'sent' ? 'sent' : null }) };
    },
  });
  vm.runInContext(fs.readFileSync(path.join(web, 'hv.js'), 'utf8'), context);
  await new Promise(setImmediate);
  return { nodes, calls };
}

test('HV controls stay disabled without completed Relapse or matching handoff', async () => {
  for (const options of [{ state: 'pending' }, { state: 'sent' }, { handoff: null }, { handoff: 'old-run' }]) {
    const { nodes, calls } = await hvPage(options);
    assert.equal(nodes['loader-ready'].disabled, true);
    nodes['loader-ready'].checked = true;
    nodes['loader-ready'].listeners.change();
    assert.equal(nodes['send-payload'].disabled, true);
    await nodes['send-payload'].listeners.click();
    assert.equal(calls.filter(c => c.options.method === 'POST').length, 0);
  }
});

test('lost send response cannot enable another payload send', async () => {
  const { nodes, calls } = await hvPage({ responseFails: true });
  nodes['loader-ready'].checked = true;
  nodes['loader-ready'].listeners.change();
  await nodes['send-payload'].listeners.click();
  assert.equal(nodes['send-payload'].disabled, true);
  assert.equal(nodes['loader-ready'].disabled, true);
  nodes['loader-ready'].listeners.change();
  await nodes['send-payload'].listeners.click();
  assert.equal(calls.filter(c => c.options.method === 'POST').length, 1);
  assert.equal(JSON.parse(calls.at(-1).options.body).relapse_session_id, 'same-run');
});

test('diagnostics drain waits for every batch, including an active request', async () => {
  const timers = new Map();
  let nextTimer = 0;
  const sent = [];
  let finishFirst;
  const context = vm.createContext({
    Uint8Array, URL, AbortController,
    document: { currentScript: { src: 'https://test/ps5/relapse/diagnostics.js' }, getElementById: () => node() },
    navigator: { userAgent: 'PlayStation 5/13.60' },
    fetch: async (_url, options) => {
      const body = JSON.parse(options.body);
      sent.push(body.lines);
      if (sent.length === 1) await new Promise(resolve => { finishFirst = resolve; });
      return { ok: true, json: async () => ({ ok: true, session_id: body.session_id, received: body.lines.length }) };
    },
    clearTimeout: id => timers.delete(id),
    window: { location: { href: 'https://test/ps5/relapse/' }, addEventListener() {},
      setTimeout: callback => { const id = ++nextTimer; timers.set(id, callback); return id; } },
  });
  vm.runInContext(fs.readFileSync(path.join(web, 'relapse/diagnostics.js'), 'utf8'), context);
  const diagnostics = context.window.__relapseDiagnostics;
  for (let index = 0; index < 45; index++) diagnostics.log('line ' + index);
  let complete = false;
  const draining = diagnostics.drain().then(value => { complete = value; });
  await new Promise(setImmediate);
  assert.equal(complete, false);
  finishFirst();
  await draining;
  assert.equal(complete, true);
  assert.equal(sent.flat().length, 46);
  assert.deepEqual(sent.flat().map(line => line.seq), Array.from({ length: 46 }, (_, i) => i + 1));
});
