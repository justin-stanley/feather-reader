/**
 * Server-side collection allow-list.
 *
 * FeatherReader only ever needs to read/write RSS records under the community
 * lexicon namespace `community.lexicon.rss.*` (subscriptions + read-state). We
 * enforce that bound *here*, on the sidecar, on every `com.atproto.repo.*` write
 * (create / put / delete / applyWrites) and on list. This means even a fully
 * compromised Rust app — or a leaked internal secret — can only touch RSS
 * records in the user's PDS, never their posts, follows, profile, or any other
 * collection.
 *
 * Matching is exact-segment: the collection NSID must equal
 * `community.lexicon.rss` or be a descendant (`community.lexicon.rss.<...>`).
 * A prefix like `community.lexicon.rssfoo` is rejected (the boundary must be a
 * dot), as is anything else.
 */

/** The namespace all FeatherReader records live under. */
export const ALLOWED_COLLECTION_ROOT = 'community.lexicon.rss';

/**
 * True iff `collection` is the allowed root or a dotted descendant of it. Also
 * enforces a minimal NSID shape (dotted, non-empty segments) so junk like `""`,
 * `"..."`, or a trailing dot is rejected before it can reach the PDS.
 */
export function isAllowedCollection(collection: unknown): collection is string {
  if (typeof collection !== 'string' || collection.length === 0) return false;
  // Reject anything that isn't a well-formed dotted NSID (no empty segments).
  if (!/^[a-zA-Z][a-zA-Z0-9-]*(\.[a-zA-Z][a-zA-Z0-9-]*)+$/.test(collection)) return false;
  return (
    collection === ALLOWED_COLLECTION_ROOT ||
    collection.startsWith(`${ALLOWED_COLLECTION_ROOT}.`)
  );
}
