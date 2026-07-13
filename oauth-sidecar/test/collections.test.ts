import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isAllowedCollection, ALLOWED_COLLECTION_ROOT } from '../src/collections.js';

test('allows the root namespace', () => {
  assert.ok(isAllowedCollection(ALLOWED_COLLECTION_ROOT));
});

test('allows descendants', () => {
  assert.ok(isAllowedCollection('community.lexicon.rss.feed'));
  assert.ok(isAllowedCollection('community.lexicon.rss.readState'));
  assert.ok(isAllowedCollection('community.lexicon.rss.sub.item'));
});

test('rejects other collections', () => {
  for (const c of [
    'app.bsky.feed.post',
    'app.bsky.actor.profile',
    'app.bsky.graph.follow',
    'com.atproto.repo.strongRef',
    'chat.bsky.convo.message',
  ]) {
    assert.equal(isAllowedCollection(c), false, `should reject ${c}`);
  }
});

test('rejects prefix-collision (no dot boundary)', () => {
  assert.equal(isAllowedCollection('community.lexicon.rssfoo'), false);
  assert.equal(isAllowedCollection('community.lexicon.rssattack.post'), false);
});

test('rejects malformed / junk NSIDs', () => {
  for (const c of ['', '.', '...', 'community.lexicon.rss.', 'community..rss', 'nodots', 42, null, undefined, {}]) {
    assert.equal(isAllowedCollection(c as unknown), false, `should reject ${JSON.stringify(c)}`);
  }
});
