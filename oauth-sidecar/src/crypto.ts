/**
 * Application-layer at-rest encryption for the sidecar's secrets.
 *
 * Everything the sidecar persists that is security-sensitive — the atproto
 * OAuth access/refresh tokens + DPoP key material (the per-DID
 * `NodeSavedSession`), the short-lived per-auth-request state, and the
 * confidential-client signing JWK — is AEAD-encrypted *before* it touches the
 * SQLite volume (or, for the JWK, the disk file). The key comes only from the
 * `SIDECAR_ENC_KEY` process env (delivered via `fly secrets`, never written to
 * the volume), so a raw volume/snapshot read is useless without the running
 * process's environment.
 *
 * Construction: AES-256-GCM (a vetted AEAD from `node:crypto`), random 96-bit
 * nonce per record, 128-bit auth tag. Ciphertext is serialized as a
 * self-describing string:
 *
 *     enc.v1.gcm.<base64url(nonce)>.<base64url(tag)>.<base64url(ciphertext)>
 *
 * The `enc.v1.` prefix lets {@link maybeDecrypt} do migrate-on-read: a stored
 * value without the prefix is treated as legacy plaintext and returned as-is,
 * so an existing DB written before encryption was enabled keeps working and is
 * transparently re-encrypted the next time its row is written.
 *
 * The 32-byte key is derived from `SIDECAR_ENC_KEY` so operators can supply it
 * as raw base64/base64url/hex (exactly 32 bytes decoded) *or* as an arbitrary
 * passphrase (hashed to 32 bytes with a domain-separated SHA-256). The
 * fail-loud length guard in `config.ts` still requires a strong value in prod.
 */

import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  createHash,
  timingSafeEqual,
} from 'node:crypto';

const ALGO = 'aes-256-gcm';
const PREFIX = 'enc.v1.gcm.';
const NONCE_LEN = 12; // 96-bit GCM nonce
const TAG_LEN = 16; // 128-bit GCM auth tag
const KEY_LEN = 32; // AES-256

function b64urlEncode(buf: Buffer): string {
  return buf.toString('base64url');
}

function b64urlDecode(s: string): Buffer {
  return Buffer.from(s, 'base64url');
}

/**
 * If `raw` is EXACTLY a 32-byte key encoded as hex or base64/base64url, return
 * those raw bytes; otherwise `null`. `Buffer.from(_, 'base64')` decodes
 * leniently (it silently drops invalid chars), so a passphrase that merely
 * happens to be base64-shaped could decode to 32 bytes — we guard against that
 * by requiring the decoded bytes to RE-ENCODE back to the input, i.e. it really
 * was a canonical 32-byte key, not a coincidence.
 */
function decodeExactKey(raw: string): Buffer | null {
  if (/^[0-9a-fA-F]{64}$/.test(raw)) {
    return Buffer.from(raw, 'hex');
  }
  const b = Buffer.from(raw, 'base64');
  if (b.length !== KEY_LEN) return null;
  // Round-trip check: accept standard base64 (with or without trailing padding)
  // and base64url. A lenient-but-non-canonical string fails all three.
  const std = b.toString('base64');
  if (raw === std || raw === std.replace(/=+$/, '') || raw === b.toString('base64url')) {
    return b;
  }
  return null;
}

/**
 * Derive the 32-byte AES key from the raw `SIDECAR_ENC_KEY` value.
 *
 * A value that is EXACTLY a 32-byte key (hex or canonical base64/base64url) is
 * used directly; anything else is treated as a passphrase and hashed with a
 * domain-separated SHA-256. Deterministic — the same env value always maps to
 * the same key, so restarts and rolling deploys decrypt existing rows.
 */
export function deriveKey(raw: string): Buffer {
  const exact = decodeExactKey(raw);
  if (exact) return exact;
  // Fall back to a domain-separated hash of the passphrase.
  return createHash('sha256').update('featherreader-sidecar-enc:v1:').update(raw, 'utf8').digest();
}

/** A bound encryptor/decryptor holding the derived key. */
export class Aead {
  private readonly key: Buffer;

  constructor(rawKey: string) {
    this.key = deriveKey(rawKey);
    if (this.key.length !== KEY_LEN) {
      throw new Error('SIDECAR_ENC_KEY: derived key is not 32 bytes');
    }
  }

  /** Encrypt UTF-8 plaintext → self-describing `enc.v1.gcm.…` token. */
  encrypt(plaintext: string): string {
    const nonce = randomBytes(NONCE_LEN);
    const cipher = createCipheriv(ALGO, this.key, nonce);
    const ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();
    return `${PREFIX}${b64urlEncode(nonce)}.${b64urlEncode(tag)}.${b64urlEncode(ct)}`;
  }

  /** True if `value` is one of our ciphertext tokens (vs. legacy plaintext). */
  static isCiphertext(value: string): boolean {
    return value.startsWith(PREFIX);
  }

  /** Decrypt a `enc.v1.gcm.…` token. Throws on a malformed/tampered token. */
  decrypt(token: string): string {
    if (!Aead.isCiphertext(token)) {
      throw new Error('not an enc.v1 ciphertext token');
    }
    const rest = token.slice(PREFIX.length);
    const parts = rest.split('.');
    if (parts.length !== 3) throw new Error('malformed ciphertext token');
    const nonce = b64urlDecode(parts[0]!);
    const tag = b64urlDecode(parts[1]!);
    const ct = b64urlDecode(parts[2]!);
    if (nonce.length !== NONCE_LEN) throw new Error('bad nonce length');
    if (tag.length !== TAG_LEN) throw new Error('bad tag length');
    const decipher = createDecipheriv(ALGO, this.key, nonce);
    decipher.setAuthTag(tag);
    const pt = Buffer.concat([decipher.update(ct), decipher.final()]);
    return pt.toString('utf8');
  }

  /**
   * Migrate-on-read: decrypt if the value is one of our tokens, otherwise treat
   * it as legacy plaintext and return it unchanged. Callers re-`encrypt` on the
   * next write, transparently upgrading old rows.
   */
  maybeDecrypt(value: string): string {
    return Aead.isCiphertext(value) ? this.decrypt(value) : value;
  }
}

/**
 * A no-op codec used in dev when no `SIDECAR_ENC_KEY` is set: values are stored
 * and read as plaintext. Prod requires a real key (see `config.ts`), so this
 * only ever runs on a localhost dev stack.
 */
export class NullCodec {
  encrypt(plaintext: string): string {
    return plaintext;
  }

  maybeDecrypt(value: string): string {
    return value;
  }
}

export type Codec = Aead | NullCodec;

/** Constant-time string compare (used for the dev-default secret guard). */
export function constantTimeEquals(a: string, b: string): boolean {
  const ab = Buffer.from(a, 'utf8');
  const bb = Buffer.from(b, 'utf8');
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}
