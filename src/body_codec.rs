//! Stored article bodies, compressed (#336).
//!
//! **Why:** bodies are about three quarters of the database file, and storage,
//! not throughput, is what limits how many feeds one machine holds (#263).
//! Deflate at level 6 measured 2.78x on 3,190 real bodies from 50 feeds, at
//! about 70 µs to compress a typical one and under a millisecond to decompress
//! the worst; zstd was no smaller without a dictionary and needs a C library
//! (the spike's numbers are on #336).
//!
//! **Format:** one tag byte, then the codec's bytes. The tag is what lets a
//! later release change codec without another column: a reader that meets a
//! tag it doesn't know treats the blob as no body, never as text.
//!
//! **Bounded on the way out.** A blob is decompressed to at most `max` bytes,
//! the cap the body was stored under, so a corrupt or tampered row can't
//! inflate without limit. Anything over it, corrupt, of an unknown tag, or not
//! UTF-8 decodes to `None`, which the caller treats as "no body here".

use std::io::Write;

/// Deflate (RFC 1951), level 6, via `flate2`'s pure-Rust `miniz_oxide` backend.
pub const TAG_DEFLATE: u8 = 1;

const LEVEL: u32 = 6;

/// `html` compressed, tagged.
pub fn encode(html: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(html.len() / 2 + 8);
    out.push(TAG_DEFLATE);
    let mut enc = flate2::write::DeflateEncoder::new(out, flate2::Compression::new(LEVEL));
    // Writing to a `Vec` cannot fail.
    enc.write_all(html.as_bytes())
        .expect("deflating into a Vec cannot fail");
    enc.finish().expect("deflating into a Vec cannot fail")
}

/// The body in `blob`, if it is a well-formed tagged body of at most `max`
/// bytes of UTF-8. `None` for anything else.
///
/// **Complete or nothing.** The deflate stream must reach its end marker and
/// use every input byte. `flate2`'s `Read` adapter stops quietly at the end of
/// its input, so a truncated blob read through it came back as a shorter body
/// (found by this module's tests); a cut-off article must be no body, never a
/// partial one shown as whole.
pub fn decode(blob: &[u8], max: usize) -> Option<String> {
    use flate2::{Decompress, FlushDecompress, Status};
    let (&tag, rest) = blob.split_first()?;
    if tag != TAG_DEFLATE {
        return None;
    }
    let mut inflate = Decompress::new(false); // raw deflate, no zlib header
    let mut out: Vec<u8> = Vec::with_capacity(rest.len().saturating_mul(4).clamp(64, max + 1));
    loop {
        if out.len() == out.capacity() {
            if out.len() > max {
                return None;
            }
            // Grow toward the cap, never past cap + 1: one byte over is enough
            // to know the body is too big.
            let more = out.capacity().max(1024).min(max + 1 - out.len());
            out.reserve_exact(more);
        }
        let consumed = inflate.total_in() as usize;
        let produced = out.len();
        // `None`, not `Finish`: with `Finish` the backend wants the whole
        // output in one call and errors on every call after the buffer first
        // runs short (measured), so a body larger than the first buffer never
        // decoded. Completeness is checked by `StreamEnd` instead.
        let status = inflate
            .decompress_vec(&rest[consumed..], &mut out, FlushDecompress::None)
            .ok()?;
        if out.len() > max {
            return None;
        }
        if status == Status::StreamEnd {
            break;
        }
        let progressed = inflate.total_in() as usize != consumed || out.len() != produced;
        if !progressed && out.len() < out.capacity() {
            // Room to write and nothing moved: the input ran out mid-stream.
            return None;
        }
    }
    if inflate.total_in() as usize != rest.len() {
        return None; // bytes after the end of the stream
    }
    String::from_utf8(out).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAX: usize = 2 * 1024 * 1024;

    fn tagged_deflate(bytes: &[u8]) -> Vec<u8> {
        let mut enc =
            flate2::write::DeflateEncoder::new(vec![TAG_DEFLATE], flate2::Compression::new(6));
        enc.write_all(bytes).unwrap();
        enc.finish().unwrap()
    }

    #[test]
    fn a_body_round_trips_byte_for_byte() {
        for body in [
            "",
            "<p>plain</p>",
            "<p>Ünïcödé — 日本語 — emoji 🦀 — RTL مرحبا</p>",
            &"<p>a long, repetitive article body. </p>".repeat(5_000),
        ] {
            let z = encode(body);
            assert_eq!(z[0], TAG_DEFLATE);
            assert_eq!(
                decode(&z, MAX).as_deref(),
                Some(body),
                "{} bytes",
                body.len()
            );
        }
    }

    #[test]
    fn a_typical_body_is_smaller_compressed() {
        let body = "<p>Some ordinary prose with a <a href=\"https://example.com/\">link</a>.</p>\n"
            .repeat(80);
        assert!(encode(&body).len() * 2 < body.len());
    }

    /// The bound: exactly the cap decodes; one byte over is no body, however
    /// small the blob that inflates to it.
    #[test]
    fn decoding_is_bounded_by_the_cap() {
        let at_cap = "a".repeat(MAX);
        assert_eq!(decode(&encode(&at_cap), MAX).map(|s| s.len()), Some(MAX));
        let over = "a".repeat(MAX + 1);
        let z = encode(&over);
        assert!(z.len() < 16 * 1024, "the bomb is small: {} bytes", z.len());
        assert_eq!(decode(&z, MAX), None);
    }

    #[test]
    fn anything_malformed_is_no_body() {
        assert_eq!(decode(&[], MAX), None, "empty");
        assert_eq!(decode(&[TAG_DEFLATE], MAX), None, "a tag with no stream");
        let mut unknown = encode("<p>x</p>");
        unknown[0] = 2;
        assert_eq!(decode(&unknown, MAX), None, "unknown tag");
        assert_eq!(
            decode(&[TAG_DEFLATE, 0xff, 0x00, 0x13, 0x37], MAX),
            None,
            "corrupt stream"
        );
        assert_eq!(
            decode(&tagged_deflate(&[0xff, 0xfe, 0xfd]), MAX),
            None,
            "not UTF-8"
        );
        // Cut anywhere short of the end, a stream is no body, not a shorter
        // one: flate2's Read adapter returned the prefix (found by this test).
        let whole = encode(&"<p>some distinct text, line by line.</p>\n".repeat(400));
        for cut in [1, 2, whole.len() / 4, whole.len() / 2, whole.len() - 1] {
            assert_eq!(
                decode(&whole[..cut], MAX),
                None,
                "truncated at {cut} of {}",
                whole.len()
            );
        }
        let mut trailing = encode("<p>x</p>");
        trailing.extend_from_slice(b"junk");
        assert_eq!(decode(&trailing, MAX), None, "bytes after the stream");
    }
}
