import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import {
  redact,
  compilePolicy,
  createVault,
  pseudonymize,
  surrogate,
  fpe,
  hmacFingerprint,
  TransformSecretError,
} from '../dist/index.js';
import { redactStream } from '../dist/stream.js';
import { createGateway, resolveConfig, GatewayConfigError } from '../dist/gateway/index.js';

const INPUT = 'mail alice@corp.com and card 4242 4242 4242 4242';
const KEYED_MODES = ['hash', 'pseudonym', 'surrogate', 'fpe'];
const MESSAGE = /non-empty transformSecret is required for hash, pseudonym and surrogate modes/;

test('every keyed mode throws the same TransformSecretError without a secret', () => {
  for (const mode of KEYED_MODES) {
    assert.throws(
      () => redact(INPUT, { mode }),
      (error) => error instanceof TransformSecretError
        && error.code === 'ERR_TRANSFORM_SECRET'
        && MESSAGE.test(error.message),
      `expected a unified TransformSecretError for mode ${mode}`,
    );
  }
});

test('the error is raised when the policy is compiled, before any value is seen', () => {
  for (const mode of KEYED_MODES) {
    assert.throws(() => compilePolicy({ mode }), { code: 'ERR_TRANSFORM_SECRET' });
  }
  // Inputs with no finding must fail too: the misconfiguration itself is the problem.
  assert.throws(() => redact('nothing sensitive here', { mode: 'hash' }), { code: 'ERR_TRANSFORM_SECRET' });
});

test('mask and label keep working without a secret', () => {
  assert.equal(redact(INPUT), 'mail a***@*** and card **** **** **** 4242');
  assert.equal(redact(INPUT, { mode: 'label' }), 'mail [REDACTED:email] and card [REDACTED:credit_card]');
});

test('keyed modes with a configured secret are unchanged and stable', () => {
  for (const mode of ['hash', 'pseudonym', 'surrogate']) {
    const opts = { mode, transformSecret: 'service-transform-secret' };
    const once = redact(INPUT, opts);
    assert.doesNotMatch(once, /alice@corp\.com|4242 4242 4242 4242/);
    assert.equal(redact(INPUT, opts), once);
  }
  // The deprecated hashSalt alias is still honoured.
  assert.equal(
    redact(INPUT, { mode: 'hash', hashSalt: 'legacy-salt' }),
    redact(INPUT, { mode: 'hash', hashSalt: 'legacy-salt' }),
  );
});

test('standalone keyed primitives refuse empty keys with the same error', () => {
  for (const fn of [
    () => pseudonymize('abc', ''),
    () => fpe('abc', ''),
    () => surrogate('abc', { id: 'email' }, ''),
    () => hmacFingerprint('', 'value'),
  ]) {
    assert.throws(fn, { code: 'ERR_TRANSFORM_SECRET', name: 'TransformSecretError' });
  }
  assert.doesNotThrow(() => pseudonymize('abc', 'k'));
});

test('a vault with a keyed mode refuses to start without a secret', () => {
  for (const mode of KEYED_MODES) {
    assert.throws(() => createVault({ mode }), { code: 'ERR_TRANSFORM_SECRET' });
  }
  // The default reversible vault is not keyed and stays available keyless.
  const vault = createVault();
  assert.match(vault.redact('mail alice@corp.com'), /\[FR_EMAIL_[0-9a-f]{24}\]/);
});

test('redactStream fails closed on a keyed mode without a secret', async () => {
  await new Promise((resolve) => {
    const stream = redactStream({ mode: 'hash' });
    stream.on('error', (error) => {
      assert.equal(error.code, 'ERR_TRANSFORM_SECRET');
      assert.match(error.message, MESSAGE);
      resolve();
    });
    stream.end(INPUT);
  });
});

test('redactStream with a configured secret still redacts', async () => {
  const out = await new Promise((resolve, reject) => {
    const chunks = [];
    const stream = redactStream({ mode: 'hash', transformSecret: 'stream-secret' });
    stream.on('data', (chunk) => chunks.push(chunk.toString()));
    stream.on('end', () => resolve(chunks.join('')));
    stream.on('error', reject);
    stream.end('mail alice@corp.com\n');
  });
  assert.match(out, /email_[0-9a-f]{32}/);
});

test('the gateway rejects a keyless keyed policy at startup', () => {
  for (const mode of KEYED_MODES) {
    assert.throws(
      () => resolveConfig({ listen: { port: 0 }, upstream: 'http://127.0.0.1:9', policy: { mode } }),
      (error) => error instanceof GatewayConfigError && MESSAGE.test(error.message),
    );
  }
  assert.throws(
    () => resolveConfig({
      listen: { port: 0 },
      routes: [{ prefix: '/', upstream: 'http://127.0.0.1:9', policy: { mode: 'pseudonym' } }],
    }),
    (error) => error instanceof GatewayConfigError && /route "\/" policy/.test(error.message),
  );
});

test('the gateway starts when the keyed policy carries a secret', () => {
  const config = resolveConfig({
    listen: { port: 0 },
    upstream: 'http://127.0.0.1:9',
    policy: { mode: 'hash', transformSecret: 'gateway-secret' },
  });
  assert.equal(config.policy.mode, 'hash');
});

test('the gateway answers a keyless keyed request with 400 and the unified code', async () => {
  const gateway = createGateway(resolveConfig({ listen: { port: 0 }, upstream: 'http://127.0.0.1:9' }));
  await gateway.listen();
  const { port } = gateway.server.address();
  try {
    const denied = await fetch(`http://127.0.0.1:${port}/v1/redact`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ input: INPUT, options: { mode: 'hash' } }),
    });
    assert.equal(denied.status, 400);
    const payload = await denied.json();
    assert.equal(payload.code, 'ERR_TRANSFORM_SECRET');
    assert.match(payload.message, MESSAGE);

    const allowed = await fetch(`http://127.0.0.1:${port}/v1/redact`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ input: INPUT }),
    });
    assert.equal(allowed.status, 200);
  } finally {
    await gateway.close();
  }
});

test('the CLI refuses keyed modes with exit code 2 and the unified message', () => {
  for (const mode of KEYED_MODES) {
    let stderr = '';
    assert.throws(
      () => execFileSync(process.execPath, ['bin/flare-redact.mjs', '--mode', mode], {
        input: INPUT,
        env: { PATH: process.env.PATH, FLARE_REDACT_SECRET: '' },
      }),
      (error) => error.status === 2 && MESSAGE.test((stderr = error.stderr.toString())),
      `CLI mode ${mode} should exit 2 with the unified message (got: ${stderr})`,
    );
  }
});

test('the CLI succeeds for a keyed mode when FLARE_REDACT_SECRET is set', () => {
  const out = execFileSync(process.execPath, ['bin/flare-redact.mjs', '--mode', 'hash'], {
    input: 'mail alice@corp.com',
    env: { PATH: process.env.PATH, FLARE_REDACT_SECRET: 'cli-transform-secret' },
  }).toString();
  assert.match(out, /email_[0-9a-f]{32}/);
});
