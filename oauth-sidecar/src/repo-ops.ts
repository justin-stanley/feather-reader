/**
 * The `/internal/repo` operations that need more than a pass-through, kept out
 * of `server.ts` so they can be tested without booting the server.
 *
 * `put` is here because of `swapRecord` (#149): the Rust reader does a
 * read-modify-write on a subscription and passes the CID it read, so a write
 * that another atproto client made in between is refused by the PDS with
 * `InvalidSwap` instead of being silently overwritten. Dropping the field on
 * this hop would turn that compare-and-swap back into a blind write with every
 * test on the Rust side still green, which is why the call is asserted here on
 * what reaches `agent.com.atproto.repo.putRecord`.
 */
import { ALLOWED_COLLECTION_ROOT, isAllowedCollection } from './collections.js';

/** The subset of `com.atproto.repo.putRecord`'s input this sidecar sends. */
export interface PutRecordInput {
  repo: string;
  collection: string;
  rkey: string;
  record: Record<string, unknown>;
  /** Compare-and-swap: the CID the caller read. Absent means "write anyway". */
  swapRecord?: string;
}

/** What `put` needs of `agent.com.atproto.repo` — a seam for the tests. */
export interface RepoPutApi {
  putRecord(input: PutRecordInput): Promise<{ data: unknown }>;
}

/** The fields of an `/internal/repo` body that `put` reads, unvalidated. */
export interface PutBody {
  collection?: unknown;
  rkey?: unknown;
  record?: unknown;
  swapRecord?: unknown;
}

/** A refusal the route answers itself, or the PDS's success payload. */
export type OpResult =
  | { ok: true; data: unknown }
  | { ok: false; code: number; error: string; message: string };

/**
 * Upper bound on a CID string. A sha-256 CIDv1 in base32 is 59 characters; the
 * bound only exists so a hostile body cannot hand the PDS an unbounded string.
 */
const MAX_CID_LENGTH = 512;

/**
 * Whether `value` is plausibly a CID string: CIDv1 in base32 (multibase `b`,
 * which is what every atproto record CID is) or a CIDv0 (`Qm…`, base58btc).
 *
 * A shape check, not a parse — the PDS parses it. Its job is to stop anything
 * that is not a string CID (a number, an object, an empty string) from becoming
 * a `swapRecord` the PDS would reject as `InvalidRequest`, which the Rust side
 * would then report as a failed write rather than as the caller's mistake.
 */
export function isCid(value: unknown): value is string {
  if (typeof value !== 'string' || value.length > MAX_CID_LENGTH) return false;
  return (
    /^b[a-z2-7]{8,}$/.test(value) || /^Qm[1-9A-HJ-NP-Za-km-z]{44}$/.test(value)
  );
}

function badRequest(message: string): OpResult {
  return { ok: false, code: 400, error: 'BadRequest', message };
}

/**
 * `put`: validate, then `putRecord`, passing `swapRecord` through when given.
 *
 * An absent `swapRecord` is OMITTED from the input rather than sent as
 * `undefined` or `null`: `null` is a different instruction in the lexicon
 * ("the record must not exist"), and nothing on the Rust side means that.
 */
export async function putRecordOp(
  api: RepoPutApi,
  did: string,
  body: PutBody,
): Promise<OpResult> {
  if (!body.collection) return badRequest('collection required for put');
  if (!isAllowedCollection(body.collection)) {
    return {
      ok: false,
      code: 403,
      error: 'CollectionNotAllowed',
      message: `collection ${JSON.stringify(body.collection)} is outside the allowed namespace ${ALLOWED_COLLECTION_ROOT}.*`,
    };
  }
  if (typeof body.rkey !== 'string' || body.rkey.length === 0)
    return badRequest('rkey required for put');
  if (
    typeof body.record !== 'object' ||
    body.record === null ||
    Array.isArray(body.record)
  )
    return badRequest('record required for put');
  if (body.swapRecord !== undefined && !isCid(body.swapRecord))
    return badRequest('swapRecord must be a CID string when present');

  const input: PutRecordInput = {
    repo: did,
    collection: body.collection,
    rkey: body.rkey,
    record: body.record as Record<string, unknown>,
  };
  if (body.swapRecord !== undefined) input.swapRecord = body.swapRecord;
  const res = await api.putRecord(input);
  return { ok: true, data: res.data };
}

/**
 * The `/internal/repo` error envelope for a thrown repo error.
 *
 * Carries the PDS's HTTP status and XRPC error name through, so the Rust side
 * can tell `InvalidSwap` (someone else wrote the record) from every other
 * failure. `@atproto/api` throws an `XRPCError` (for `putRecord`, a
 * `ComAtprotoRepoPutRecord.InvalidSwapError`) with a numeric `status` and the
 * name in `error`; anything else is a 502 `RepoOpFailed`.
 */
export function repoErrorReply(err: unknown): {
  status: number;
  body: { ok: false; error: string; message: string; status: number };
} {
  const anyErr = err as {
    status?: unknown;
    error?: unknown;
    message?: unknown;
  };
  const status = typeof anyErr.status === 'number' ? anyErr.status : 502;
  return {
    status,
    body: {
      ok: false,
      error: typeof anyErr.error === 'string' ? anyErr.error : 'RepoOpFailed',
      message:
        typeof anyErr.message === 'string' ? anyErr.message : String(err),
      status,
    },
  };
}
