/**
 * Tests for the rate-limit key (`src/client-ip.ts`).
 *
 * The deployed chain is
 * `visitor → Cloudflare → Fly proxy → Caddy → sidecar`, and each hop changes
 * what "the peer" means. Picking the wrong header does not fail loudly — it
 * silently changes *who shares a rate-limit bucket*, which surfaces either as
 * unexplained 429s for innocent users or as a throttle that does not throttle.
 * These tests pin the precedence so that choice cannot drift again unnoticed.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { IncomingHttpHeaders } from 'node:http';
import { clientIp } from '../src/client-ip.js';

/** The in-container Caddy hop makes the socket peer permanently loopback. */
const LOOPBACK = '127.0.0.1';

function req(headers: IncomingHttpHeaders, ip: string = LOOPBACK) {
  return { headers, ip };
}

// ─── Precedence ──────────────────────────────────────────────────────────────

test('prefers cf-connecting-ip: it is the only header carrying the true visitor', () => {
  // Behind Cloudflare, Fly's proxy sees the CF edge — so fly-client-ip is the
  // edge IP, not the visitor. Keying on it would put every visitor behind that
  // edge IP into one shared bucket.
  const ip = clientIp(
    req({ 'cf-connecting-ip': '203.0.113.7', 'fly-client-ip': '198.51.100.1' }),
  );

  assert.equal(ip, '203.0.113.7');
});

test('falls back to fly-client-ip when Cloudflare is not in front', () => {
  // A CF-less deployment: Fly is the outermost proxy, so its header *is* the
  // visitor.
  assert.equal(clientIp(req({ 'fly-client-ip': '198.51.100.1' })), '198.51.100.1');
});

test('falls back to the socket peer when neither platform header is present', () => {
  assert.equal(clientIp(req({})), LOOPBACK);
});

test('two visitors behind one Cloudflare edge IP get distinct keys', () => {
  // This is the regression the precedence fix exists for: under the old
  // fly-first ordering both of these collapsed to the same edge IP, so one
  // visitor could exhaust the /login budget for the other.
  const edge = '198.51.100.1';
  const a = clientIp(req({ 'cf-connecting-ip': '203.0.113.7', 'fly-client-ip': edge }));
  const b = clientIp(req({ 'cf-connecting-ip': '203.0.113.8', 'fly-client-ip': edge }));

  assert.notEqual(a, b);
});

// ─── Spoofing ────────────────────────────────────────────────────────────────

test('ignores X-Forwarded-For entirely, however it is dressed up', () => {
  // Any client can send this. Fastify is also constructed without trustProxy,
  // so it never reaches req.ip either.
  const ip = clientIp(
    req({
      'x-forwarded-for': '1.2.3.4',
      'x-real-ip': '5.6.7.8',
      'true-client-ip': '9.10.11.12',
    }),
  );

  assert.equal(ip, LOOPBACK);
});

test('takes the right-most entry, so a prepended forgery cannot win', () => {
  // A trusted proxy appends its observation last; anything to the left may be
  // client-supplied. Mirrors client_ip in src/web.rs, which takes
  // raw.split(',').next_back() for the same reason.
  assert.equal(
    clientIp(req({ 'cf-connecting-ip': '1.2.3.4, 203.0.113.7' })),
    '203.0.113.7',
  );
  assert.equal(
    clientIp(req({ 'fly-client-ip': '1.2.3.4, 198.51.100.1' })),
    '198.51.100.1',
  );
});

test('a forged cf-connecting-ip cannot mint unlimited fresh buckets', () => {
  // Sanity-check the property the limiter depends on: an attacker rotating the
  // left-hand side of the header still lands on one key, because only the
  // right-most (proxy-appended) entry counts.
  const keys = new Set(
    ['1.1.1.1', '2.2.2.2', '3.3.3.3'].map((forged) =>
      clientIp(req({ 'cf-connecting-ip': `${forged}, 203.0.113.7` })),
    ),
  );

  assert.deepEqual([...keys], ['203.0.113.7']);
});

// ─── Malformed input ─────────────────────────────────────────────────────────

test('an empty or whitespace-only header falls through rather than keying on ""', () => {
  // A single empty key would be a global bucket shared by every such request.
  assert.equal(clientIp(req({ 'cf-connecting-ip': '' })), LOOPBACK);
  assert.equal(clientIp(req({ 'cf-connecting-ip': '   ' })), LOOPBACK);
  assert.equal(
    clientIp(req({ 'cf-connecting-ip': '  ', 'fly-client-ip': '198.51.100.1' })),
    '198.51.100.1',
  );
});

test('a trailing comma does not produce an empty key', () => {
  assert.equal(clientIp(req({ 'cf-connecting-ip': '203.0.113.7,' })), LOOPBACK);
});

test('a repeated (array-valued) header is refused rather than guessed at', () => {
  // Node surfaces some repeated headers as string[]. Our proxies do not emit
  // these, and picking one copy as authoritative is exactly the wrong instinct.
  const headers = { 'cf-connecting-ip': ['203.0.113.7', '1.2.3.4'] } as IncomingHttpHeaders;

  assert.equal(clientIp(req(headers)), LOOPBACK);
});

test('surrounding whitespace is trimmed off the accepted value', () => {
  assert.equal(clientIp(req({ 'cf-connecting-ip': '  203.0.113.7  ' })), '203.0.113.7');
});

// ─── Shape ───────────────────────────────────────────────────────────────────

test('is usable as a @fastify/rate-limit keyGenerator (structural typing)', () => {
  // The real call site passes a FastifyRequest; the point of ClientIpSource is
  // that it accepts one without dragging Fastify into this module.
  const keyGenerator: (r: { headers: IncomingHttpHeaders; ip: string }) => string =
    clientIp;

  assert.equal(typeof keyGenerator(req({ 'cf-connecting-ip': '203.0.113.7' })), 'string');
});
