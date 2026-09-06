/**
 * Tests for the rate-limit key (`src/client-ip.ts`).
 *
 * The deployed chain is
 * `visitor → Cloudflare → Fly proxy → Caddy → sidecar`, and each hop changes
 * what "the peer" means. Reading the wrong header does not fail loudly — it
 * silently changes *who shares a rate-limit bucket*, surfacing either as
 * unexplained 429s for innocent users or as a throttle that does not throttle.
 * Which header is right is deployment configuration, so what these tests pin is
 * that the configured one is honoured exactly, and that everything else is
 * ignored.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { IncomingHttpHeaders } from 'node:http';
import { clientIp, clientIpKeyGenerator } from '../src/client-ip.js';

/** The in-container Caddy hop makes the socket peer permanently loopback. */
const LOOPBACK = '127.0.0.1';
const CF = 'cf-connecting-ip';
const FLY = 'fly-client-ip';

function req(headers: IncomingHttpHeaders, ip: string = LOOPBACK) {
  return { headers, ip };
}

// ─── Honouring the configured header ─────────────────────────────────────────

test('reads the configured header and nothing else', () => {
  // Behind Cloudflare, Fly's proxy sees the CF edge — so fly-client-ip is the
  // edge IP, not the visitor. Keying on it would put every visitor behind that
  // edge into one shared bucket.
  const headers = { [CF]: '203.0.113.7', [FLY]: '198.51.100.1' };

  assert.equal(clientIp(req(headers), CF), '203.0.113.7');
  assert.equal(clientIp(req(headers), FLY), '198.51.100.1');
});

test('two visitors behind one Cloudflare edge IP get distinct keys', () => {
  // The regression this module exists for: reading fly-client-ip behind
  // Cloudflare collapsed both of these onto the same edge IP, so one visitor
  // could exhaust the /login budget for the other.
  const edge = '198.51.100.1';
  const a = clientIp(req({ [CF]: '203.0.113.7', [FLY]: edge }), CF);
  const b = clientIp(req({ [CF]: '203.0.113.8', [FLY]: edge }), CF);

  assert.notEqual(a, b);
});

test('ignores every header that is not the configured one', () => {
  // Any client can send these; none is special-cased.
  const ip = clientIp(
    req({
      'x-forwarded-for': '1.2.3.4',
      'x-real-ip': '5.6.7.8',
      'true-client-ip': '9.10.11.12',
      [FLY]: '198.51.100.1',
    }),
    CF,
  );

  assert.equal(ip, LOOPBACK);
});

// ─── No header configured ────────────────────────────────────────────────────

test('with no header configured, keys on the socket peer', () => {
  // Prod refuses to boot in this state (see config.ts); in dev it degrades to
  // one shared bucket rather than trusting anything a client can set.
  assert.equal(clientIp(req({ [CF]: '203.0.113.7' }), null), LOOPBACK);
  assert.equal(clientIp(req({}), null), LOOPBACK);
});

// ─── Spoofing ────────────────────────────────────────────────────────────────

test('takes the right-most entry, so a prepended forgery cannot win', () => {
  // A trusted proxy appends its observation last; anything to the left may be
  // client-supplied. Mirrors client_ip in src/web.rs, which takes
  // raw.split(',').next_back() for the same reason.
  assert.equal(clientIp(req({ [CF]: '1.2.3.4, 203.0.113.7' }), CF), '203.0.113.7');
});

test('a forged prefix cannot mint unlimited fresh buckets', () => {
  // The property the limiter depends on: an attacker rotating the left-hand
  // side still lands on one key, because only the proxy-appended entry counts.
  const keys = new Set(
    ['1.1.1.1', '2.2.2.2', '3.3.3.3'].map((forged) =>
      clientIp(req({ [CF]: `${forged}, 203.0.113.7` }), CF),
    ),
  );

  assert.deepEqual([...keys], ['203.0.113.7']);
});

// ─── Malformed input ─────────────────────────────────────────────────────────

test('an empty or whitespace-only header falls through rather than keying on ""', () => {
  // A single empty key would be a global bucket shared by every such request.
  assert.equal(clientIp(req({ [CF]: '' }), CF), LOOPBACK);
  assert.equal(clientIp(req({ [CF]: '   ' }), CF), LOOPBACK);
});

test('a trailing comma does not produce an empty key', () => {
  assert.equal(clientIp(req({ [CF]: '203.0.113.7,' }), CF), LOOPBACK);
});

test('a repeated (array-valued) header is refused rather than guessed at', () => {
  // Node surfaces some repeated headers as string[]. Our proxies do not emit
  // these, and picking one copy as authoritative is exactly the wrong instinct.
  const headers = { [CF]: ['203.0.113.7', '1.2.3.4'] } as IncomingHttpHeaders;

  assert.equal(clientIp(req(headers), CF), LOOPBACK);
});

test('surrounding whitespace is trimmed off the accepted value', () => {
  assert.equal(clientIp(req({ [CF]: '  203.0.113.7  ' }), CF), '203.0.113.7');
});

// ─── keyGenerator factory ────────────────────────────────────────────────────

test('clientIpKeyGenerator binds the header once and is usable as a keyGenerator', () => {
  // The real call site passes a FastifyRequest; ClientIpSource exists so this
  // stays testable without dragging Fastify in.
  const keyGenerator: (r: { headers: IncomingHttpHeaders; ip: string }) => string =
    clientIpKeyGenerator(CF);

  assert.equal(keyGenerator(req({ [CF]: '203.0.113.7' })), '203.0.113.7');
  assert.equal(keyGenerator(req({ [FLY]: '198.51.100.1' })), LOOPBACK);
});

test('clientIpKeyGenerator(null) degrades to the socket peer', () => {
  assert.equal(clientIpKeyGenerator(null)(req({ [CF]: '203.0.113.7' })), LOOPBACK);
});

// ─── The misconfiguration boot cannot catch ──────────────────────────────────

test('a header name that is set but WRONG reports itself on first use', () => {
  // loadConfig can check SIDECAR_TRUSTED_IP_HEADER is set, not that it is
  // correct. A typo boots clean and then keys every request on the loopback
  // peer — one shared bucket for the whole site, which is the exact login
  // denial this module exists to prevent. Only live traffic reveals it.
  let reports = 0;
  const key = clientIpKeyGenerator('cf_connecting_ip', () => void reports++);

  assert.equal(key(req({ [CF]: '203.0.113.7' })), LOOPBACK);
  assert.equal(reports, 1, 'the misconfiguration must not be silent');
});

test('the report fires once, not once per request', () => {
  // Under the very traffic that makes this misconfiguration hurt, a per-request
  // log line would be its own outage.
  let reports = 0;
  const key = clientIpKeyGenerator('cf_connecting_ip', () => void reports++);

  for (let i = 0; i < 50; i++) key(req({ [CF]: '203.0.113.7' }));

  assert.equal(reports, 1);
});

test('a correctly configured header never reports', () => {
  let reports = 0;
  const key = clientIpKeyGenerator(CF, () => void reports++);

  assert.equal(key(req({ [CF]: '203.0.113.7' })), '203.0.113.7');
  assert.equal(reports, 0);
});

test('with no header configured the request path stays quiet — boot already warned', () => {
  // config.ts warns at boot for the dev/null case; re-reporting per request
  // would just be noise on a stack that is knowingly unlimited.
  let reports = 0;
  const key = clientIpKeyGenerator(null, () => void reports++);

  key(req({ [CF]: '203.0.113.7' }));

  assert.equal(reports, 0);
});
