import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Aead, NullCodec, deriveKey, constantTimeEquals } from '../src/crypto.js';

const KEY = 'a'.repeat(43); // 43 base64url chars → passphrase path (not exactly 32 bytes decoded)

test('deriveKey: 32-byte base64 used directly', () => {
  const raw = Buffer.alloc(32, 7).toString('base64');
  assert.equal(deriveKey(raw).length, 32);
  assert.ok(deriveKey(raw).equals(Buffer.alloc(32, 7)));
});

test('deriveKey: 64-char hex used directly', () => {
  const raw = 'ab'.repeat(32);
  assert.ok(deriveKey(raw).equals(Buffer.from(raw, 'hex')));
});

test('deriveKey: passphrase is hashed to 32 bytes and is deterministic', () => {
  const a = deriveKey('some-long-passphrase-value');
  const b = deriveKey('some-long-passphrase-value');
  assert.equal(a.length, 32);
  assert.ok(a.equals(b));
  assert.ok(!a.equals(deriveKey('different')));
});

test('Aead: round-trips and produces enc.v1 tokens', () => {
  const aead = new Aead(KEY);
  const ct = aead.encrypt('hello secret');
  assert.ok(ct.startsWith('enc.v1.gcm.'));
  assert.ok(Aead.isCiphertext(ct));
  assert.equal(aead.decrypt(ct), 'hello secret');
});

test('Aead: nonce is random (two encrypts differ, both decrypt)', () => {
  const aead = new Aead(KEY);
  const a = aead.encrypt('same');
  const b = aead.encrypt('same');
  assert.notEqual(a, b);
  assert.equal(aead.decrypt(a), 'same');
  assert.equal(aead.decrypt(b), 'same');
});

test('Aead: tampered ciphertext fails (auth tag)', () => {
  const aead = new Aead(KEY);
  const ct = aead.encrypt('tamperme');
  const parts = ct.split('.');
  // Flip a byte in the ciphertext segment.
  const bad = Buffer.from(parts[4]!, 'base64url');
  bad[0] ^= 0xff;
  parts[4] = bad.toString('base64url');
  assert.throws(() => aead.decrypt(parts.join('.')));
});

test('Aead: wrong key cannot decrypt', () => {
  const ct = new Aead(KEY).encrypt('cross-key');
  assert.throws(() => new Aead('totally-different-passphrase-here').decrypt(ct));
});

test('Aead.maybeDecrypt: migrate-on-read passes through legacy plaintext', () => {
  const aead = new Aead(KEY);
  assert.equal(aead.maybeDecrypt('{"legacy":true}'), '{"legacy":true}');
  const ct = aead.encrypt('{"legacy":true}');
  assert.equal(aead.maybeDecrypt(ct), '{"legacy":true}');
});

test('NullCodec: pass-through both directions', () => {
  const n = new NullCodec();
  assert.equal(n.encrypt('x'), 'x');
  assert.equal(n.maybeDecrypt('x'), 'x');
});

test('constantTimeEquals', () => {
  assert.ok(constantTimeEquals('abc', 'abc'));
  assert.ok(!constantTimeEquals('abc', 'abd'));
  assert.ok(!constantTimeEquals('abc', 'abcd'));
});
