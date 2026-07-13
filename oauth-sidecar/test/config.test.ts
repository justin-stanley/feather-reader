import { test } from 'node:test';
import assert from 'node:assert/strict';
import { loadConfig, DEV_INTERNAL_SECRET, MIN_SECRET_BYTES } from '../src/config.js';

const KEYS = [
  'SIDECAR_DEV',
  'SIDECAR_PUBLIC_URL',
  'SIDECAR_INTERNAL_SECRET',
  'SIDECAR_ENC_KEY',
  'SIDECAR_SESSION_ABS_TTL_MS',
  'SIDECAR_SESSION_IDLE_TTL_MS',
  'SIDECAR_REAPER_INTERVAL_MS',
] as const;

function withEnv(env: Record<string, string | undefined>, fn: () => void): void {
  const saved: Record<string, string | undefined> = {};
  for (const k of KEYS) saved[k] = process.env[k];
  for (const k of KEYS) delete process.env[k];
  for (const [k, v] of Object.entries(env)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  try {
    fn();
  } finally {
    for (const k of KEYS) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
  }
}

const STRONG = 'x'.repeat(MIN_SECRET_BYTES);

test('prod: missing internal secret refuses to boot', () => {
  withEnv({ SIDECAR_PUBLIC_URL: 'https://reader.example.com/oauth', SIDECAR_ENC_KEY: STRONG }, () => {
    assert.throws(() => loadConfig(), /SIDECAR_INTERNAL_SECRET is required/);
  });
});

test('prod: dev-default internal secret refuses to boot', () => {
  withEnv(
    {
      SIDECAR_PUBLIC_URL: 'https://reader.example.com/oauth',
      SIDECAR_INTERNAL_SECRET: DEV_INTERNAL_SECRET,
      SIDECAR_ENC_KEY: STRONG,
    },
    () => assert.throws(() => loadConfig(), /insecure dev default/),
  );
});

test('prod: short internal secret refuses to boot', () => {
  withEnv(
    {
      SIDECAR_PUBLIC_URL: 'https://reader.example.com/oauth',
      SIDECAR_INTERNAL_SECRET: 'short',
      SIDECAR_ENC_KEY: STRONG,
    },
    () => assert.throws(() => loadConfig(), /too short/),
  );
});

test('prod: localhost PUBLIC_URL alone does NOT enable dev bypass', () => {
  // A loopback PUBLIC_URL with no SIDECAR_DEV=true must still fail-loud.
  withEnv({ SIDECAR_PUBLIC_URL: 'http://127.0.0.1:8081' }, () => {
    assert.throws(() => loadConfig(), /SIDECAR_INTERNAL_SECRET is required/);
  });
});

test('prod: missing enc key refuses to boot', () => {
  withEnv(
    { SIDECAR_PUBLIC_URL: 'https://reader.example.com/oauth', SIDECAR_INTERNAL_SECRET: STRONG },
    () => assert.throws(() => loadConfig(), /SIDECAR_ENC_KEY is required/),
  );
});

test('prod: short enc key refuses to boot', () => {
  withEnv(
    {
      SIDECAR_PUBLIC_URL: 'https://reader.example.com/oauth',
      SIDECAR_INTERNAL_SECRET: STRONG,
      SIDECAR_ENC_KEY: 'short',
    },
    () => assert.throws(() => loadConfig(), /SIDECAR_ENC_KEY is too short/),
  );
});

test('prod: strong secret + key boots and stays non-dev', () => {
  withEnv(
    {
      SIDECAR_PUBLIC_URL: 'https://reader.example.com/oauth',
      SIDECAR_INTERNAL_SECRET: STRONG,
      SIDECAR_ENC_KEY: STRONG,
    },
    () => {
      const cfg = loadConfig();
      assert.equal(cfg.dev, false);
      assert.equal(cfg.internalSecret, STRONG);
      assert.equal(cfg.encKey, STRONG);
    },
  );
});

test('explicit SIDECAR_DEV=true allows defaults + plaintext', () => {
  withEnv({ SIDECAR_DEV: 'true', SIDECAR_PUBLIC_URL: 'https://reader.example.com/oauth' }, () => {
    const cfg = loadConfig();
    assert.equal(cfg.internalSecret, DEV_INTERNAL_SECRET);
    assert.equal(cfg.encKey, undefined);
  });
});

test('TTL env overrides parse; bad values throw', () => {
  withEnv(
    {
      SIDECAR_DEV: 'true',
      SIDECAR_SESSION_ABS_TTL_MS: '123',
      SIDECAR_SESSION_IDLE_TTL_MS: '45',
      SIDECAR_REAPER_INTERVAL_MS: '9',
    },
    () => {
      const cfg = loadConfig();
      assert.equal(cfg.sessionAbsoluteTtlMs, 123);
      assert.equal(cfg.sessionIdleTtlMs, 45);
      assert.equal(cfg.reaperIntervalMs, 9);
    },
  );
  withEnv({ SIDECAR_DEV: 'true', SIDECAR_REAPER_INTERVAL_MS: 'nope' }, () => {
    assert.throws(() => loadConfig(), /expected a positive integer/);
  });
});
