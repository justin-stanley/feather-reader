import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ComAtprotoRepoPutRecord, XRPCError } from '@atproto/api';
import {
  isCid,
  putRecordOp,
  repoErrorReply,
  type PutRecordInput,
  type RepoPutApi,
} from '../src/repo-ops.js';

const DID = 'did:plc:ewvi7nxzyoun6zhxrhs64oiz';
const COLLECTION = 'community.lexicon.rss.subscription';
const CID = 'bafyreigh2akiscaildcqabsyg3dfr6chu3fgpregiymsck7e7aqa4s52zy';

/** A fake `agent.com.atproto.repo` that records every putRecord input. */
function capturingApi(): { api: RepoPutApi; calls: PutRecordInput[] } {
  const calls: PutRecordInput[] = [];
  return {
    calls,
    api: {
      async putRecord(input) {
        calls.push(input);
        return { data: { uri: `at://${DID}/${COLLECTION}/rk`, cid: CID } };
      },
    },
  };
}

const record = { $type: COLLECTION, url: 'https://example.com/feed.xml' };

test('put passes swapRecord through to putRecord (#149)', async () => {
  const { api, calls } = capturingApi();
  const out = await putRecordOp(api, DID, {
    collection: COLLECTION,
    rkey: 'rk',
    record,
    swapRecord: CID,
  });
  assert.equal(out.ok, true);
  assert.equal(calls.length, 1);
  assert.equal(
    calls[0]?.swapRecord,
    CID,
    'the compare-and-swap CID was dropped',
  );
  assert.equal(calls[0]?.repo, DID);
  assert.equal(calls[0]?.rkey, 'rk');
  assert.deepEqual(calls[0]?.record, record);
});

test('put without swapRecord sends no swapRecord key at all', async () => {
  const { api, calls } = capturingApi();
  const out = await putRecordOp(api, DID, {
    collection: COLLECTION,
    rkey: 'rk',
    record,
  });
  assert.equal(out.ok, true);
  assert.equal(calls.length, 1);
  assert.ok(
    !('swapRecord' in (calls[0] as object)),
    `an absent swap must be omitted, not sent: ${JSON.stringify(calls[0])}`,
  );
});

test('a swapRecord that is not a CID string is refused before the PDS', async () => {
  for (const bad of [
    '',
    42,
    null,
    {},
    'not a cid',
    'bafy rei',
    `b${'a'.repeat(600)}`,
  ]) {
    const { api, calls } = capturingApi();
    const out = await putRecordOp(api, DID, {
      collection: COLLECTION,
      rkey: 'rk',
      record,
      swapRecord: bad,
    });
    assert.equal(out.ok, false, `accepted ${JSON.stringify(bad)}`);
    if (!out.ok) {
      assert.equal(out.code, 400);
      assert.equal(out.error, 'BadRequest');
    }
    assert.equal(calls.length, 0, `${JSON.stringify(bad)} reached the PDS`);
  }
});

test('the existing put requirements still hold', async () => {
  const cases: Array<[Record<string, unknown>, number]> = [
    [{ rkey: 'rk', record }, 400],
    [{ collection: 'app.bsky.feed.post', rkey: 'rk', record }, 403],
    [{ collection: COLLECTION, record }, 400],
    [{ collection: COLLECTION, rkey: 'rk' }, 400],
  ];
  for (const [body, code] of cases) {
    const { api, calls } = capturingApi();
    const out = await putRecordOp(api, DID, body);
    assert.equal(out.ok, false, JSON.stringify(body));
    if (!out.ok) assert.equal(out.code, code, JSON.stringify(body));
    assert.equal(calls.length, 0);
  }
});

test('isCid accepts real record CIDs and refuses junk', () => {
  assert.ok(isCid(CID));
  assert.ok(isCid('QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG'));
  for (const bad of ['', 'bafy', 'BAFYREI', 'hello world', 7, undefined]) {
    assert.equal(isCid(bad), false, JSON.stringify(bad));
  }
});

test("the PDS's InvalidSwap reaches the Rust side as status 400 InvalidSwap", () => {
  // What @atproto/api throws for a stale swapRecord: XRPCError -> toKnownErr.
  const err = new ComAtprotoRepoPutRecord.InvalidSwapError(
    new XRPCError(400, 'InvalidSwap', `Record was at ${CID}`),
  );
  const reply = repoErrorReply(err);
  assert.equal(reply.status, 400);
  assert.equal(reply.body.error, 'InvalidSwap');
  assert.equal(reply.body.status, 400);
  assert.equal(reply.body.ok, false);
});

test('an error that is not an XRPC error still maps to 502 RepoOpFailed', () => {
  const reply = repoErrorReply(new Error('socket hang up'));
  assert.equal(reply.status, 502);
  assert.equal(reply.body.error, 'RepoOpFailed');
  assert.equal(reply.body.message, 'socket hang up');
});
