const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const source = fs.readFileSync(path.join(__dirname, '../investigator/static/investigation.js'), 'utf8');

async function render(data, status = 200) {
  function element(tag) {
    return { tag, style: {}, dataset: {}, children: [], textContent: '',
      append(...children) { this.children.push(...children); },
      appendChild(child) { this.children.push(child); },
      set innerHTML(value) { throw new Error('Untrusted HTML rendering is forbidden'); } };
  }
  const nodes = Object.fromEntries(['activity', 'connection', 'spin', 'errmsg', 'failed', 'done', 'reportstatus']
    .map(id => [id, element('div')]));
  nodes.activity.dataset.runId = 'run-test';
  vm.runInNewContext(source, {
    document: { getElementById: id => nodes[id], createElement: element,
      createTextNode: text => ({ tag: '#text', textContent: text }) },
    fetch: async () => ({ status, ok: status === 200, json: async () => data }),
    AbortSignal: { timeout: () => undefined }, setTimeout: () => {}
  });
  await new Promise(resolve => setImmediate(resolve));
  return nodes;
}

test('hostile activity is inserted as literal text, with a fixed class allowlist', async () => {
  const message = '<img src=x onerror=alert(1)><script>alert(1)</script>';
  const nodes = await render({ activity: [{ at: '2026-09-30T09:00:00Z', kind: 'x" onclick="evil', message }],
    next_index: 1, status: 'completed', report_status: 'completed' });
  const row = nodes.activity.children[0];
  assert.equal(row.children[0].className, 'dot info');
  assert.equal(row.children[1].children[1].tag, '#text');
  assert.equal(row.children[1].children[1].textContent, ` ${message}`);
});

test('incomplete assessment and persistence failure remain visible', async () => {
  const nodes = await render({ activity: [], next_index: 0, status: 'completed',
    report_status: 'incomplete', persistence_error: 'disk full' });
  assert.equal(nodes.done.style.display, 'block');
  assert.match(nodes.reportstatus.textContent, /incomplete/);
  assert.match(nodes.reportstatus.textContent, /could not be saved/);
});

test('expired run ends polling and displays a recoverable error', async () => {
  const nodes = await render({}, 404);
  assert.equal(nodes.failed.style.display, 'block');
  assert.equal(nodes.spin.style.display, 'none');
  assert.match(nodes.errmsg.textContent, /no longer available/);
});
