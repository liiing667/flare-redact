import { test } from 'node:test';
import assert from 'node:assert/strict';
import { redactStream } from '../dist/stream.js';

function run(input) {
  return new Promise((resolve) => {
    const s = redactStream();
    const chunks = [];
    s.on('data', (c) => chunks.push(c.toString()));
    s.on('end', () => resolve(chunks.join('')));
    for (const line of input) s.write(line);
    s.end();
  });
}

function runWithError(opts, input) {
  return new Promise((resolve) => {
    const s = redactStream(opts);
    const chunks = [];
    s.on('data', (c) => chunks.push(c.toString()));
    s.on('error', (error) => resolve({ error, output: chunks.join('') }));
    s.on('end', () => resolve({ error: null, output: chunks.join('') }));
    for (const part of input) s.write(part);
    s.end();
  });
}

test('redactStream masks secrets line by line', async () => {
  const out = await run(['user bob@x.io\n', 'token ghp_' + 'a'.repeat(36) + '\n']);
  assert.match(out, /user b\*\*\*@\*\*\*/);
  assert.match(out, /token ghp_\*\*\*/);
});

test('redactStream handles a secret split across chunks', async () => {
  const gh = 'ghp_' + 'a'.repeat(36);
  const out = await run(['token ' + gh.slice(0, 10), gh.slice(10) + '\n']);
  assert.match(out, /token ghp_\*\*\*/);
});

test('redactStream masks a multiline private key as one record', async () => {
  const out = await run([
    'before\n-----BEGIN RSA PRIVATE KEY-----\n',
    'MIIBOgIBAAJBAKj\n-----END RSA PRIVATE KEY-----\nafter\n',
  ]);
  assert.equal(out, 'before\n[REDACTED PRIVATE KEY]\nafter\n');
});

test('redactStream fails closed for an unterminated private key', async () => {
  const out = await run(['before\n-----BEGIN PRIVATE KEY-----\n', 'secret material']);
  assert.equal(out, 'before\n[REDACTED PRIVATE KEY]');
});

test('redactStream fails closed when an unterminated key arrives without a newline', async () => {
  const out = await run(['prefix -----BEGIN PRIVATE KEY-----secret material']);
  assert.equal(out, 'prefix [REDACTED PRIVATE KEY]');
});

test('redactStream fails closed when a long line without newlines exceeds the byte budget', async () => {
  const { error, output } = await runWithError({ maxRecordLength: 64 }, ['a'.repeat(40), 'b'.repeat(40)]);
  assert.ok(error, 'expected the stream to fail closed');
  assert.equal(error.name, 'RedactionLimitError');
  assert.equal(error.code, 'ERR_REDACTION_LIMIT');
  assert.equal(output, '');
});

test('redactStream shares the byte budget with credentials split across chunks', async () => {
  const gh = 'ghp_' + 'a'.repeat(36);
  const { error, output } = await runWithError(
    { maxRecordLength: 20 },
    ['token ' + gh.slice(0, 10), gh.slice(10)],
  );
  assert.ok(error, 'expected the stream to fail closed');
  assert.equal(error.name, 'RedactionLimitError');
  assert.equal(output, '');
});

test('redactStream shares the byte budget with multiline PEM records', async () => {
  const { error, output } = await runWithError(
    { maxRecordLength: 32 },
    ['before\n-----BEGIN PRIVATE KEY-----\n', 'secret material without a footer'],
  );
  assert.ok(error, 'expected the stream to fail closed');
  assert.equal(error.name, 'RedactionLimitError');
  assert.equal(output, 'before\n');
});

test('redactStream keeps small inputs and chunk boundaries under the budget unchanged', async () => {
  const gh = 'ghp_' + 'a'.repeat(36);
  const out = await runWithError(
    { maxRecordLength: 1024 },
    ['user bob@x.io\n', 'token ' + gh.slice(0, 10), gh.slice(10) + '\n'],
  );
  assert.equal(out.error, null);
  assert.match(out.output, /user b\*\*\*@\*\*\*/);
  assert.match(out.output, /token ghp_\*\*\*/);
});

test('redactStream measures the budget in UTF-8 bytes rather than code units', async () => {
  // Each "€" is one code unit but three UTF-8 bytes: nine code units are 27 bytes.
  const { error, output } = await runWithError({ maxRecordLength: 24 }, ['€'.repeat(9)]);
  assert.ok(error, 'expected the stream to fail closed on byte length');
  assert.equal(output, '');
});

test('redactStream leaves small custom-detector inputs across chunks unchanged', async () => {
  const opts = {
    maxRecordLength: 64,
    custom: [
      { id: 'ticket', label: 'Ticket', why: 'internal id', pattern: /\bACME-\d{4,6}\b/g, mask: () => '[TICKET]', default: true },
    ],
  };
  const { error, output } = await runWithError(opts, ['ticket ACME-12', '34 done\n']);
  assert.equal(error, null);
  assert.equal(output, 'ticket [TICKET] done\n');
});
