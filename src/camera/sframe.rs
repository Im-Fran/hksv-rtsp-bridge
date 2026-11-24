//! SFrame (RFC 9605) as required by the Home remote view: group key -> base key per
//! SSRC (Apple's own step) -> key/salt per RFC 9605. Send only (the accessory does not receive
//! media). Video: AES_256_CTR_HMAC_SHA512_80; audio: AES_256_CTR_HMAC_SHA512_32.
//! Reference: cameraui/plugins `camera-ui-homekit/src/camera/sframe.ts` and `sframeRtp.ts`.

use aes::Aes256;
use ctr::Ctr128BE;
use ctr::cipher::{KeyIvInit, StreamCipher};
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha512;

/// Key ID of the key the accessory sends with.
pub const SENDER_KID: u64 = 0x100;

/// Label for the per-stream keys.
const STREAM_LABEL: &[u8] = b"SFrame 1.0 RTP Stream";

#[derive(Clone, Copy)]
pub enum Suite {
    /// Video: 10-byte label.
    Video,
    /// Audio: 4-byte label.
    Audio,
}

impl Suite {
    fn id(self) -> u16 {
        match self {
            Suite::Video => 0x0006,
            Suite::Audio => 0x0008,
        }
    }
    fn tag_len(self) -> usize {
        match self {
            Suite::Video => 10,
            Suite::Audio => 4,
        }
    }
}

fn hkdf(salt: &[u8], ikm: &[u8], info: &[u8], out: &mut [u8]) {
    let salt = if salt.is_empty() { None } else { Some(salt) };
    Hkdf::<Sha512>::new(salt, ikm)
        .expand(info, out)
        .expect("valid HKDF length");
}

/// Encrypts the frames of a stream (one SSRC). Each `protect` consumes a counter.
pub struct SFrameStream {
    enc: [u8; 32],
    auth: [u8; 64],
    salt: [u8; 12],
    suite: Suite,
    kid: u64,
    ctr: u64,
}

impl SFrameStream {
    pub fn new(group_key: &[u8], kid: u64, ssrc: u32, suite: Suite) -> Self {
        let mut base = [0u8; 64];
        hkdf(&ssrc.to_be_bytes(), group_key, STREAM_LABEL, &mut base);
        let mut suffix = kid.to_be_bytes().to_vec();
        suffix.extend_from_slice(&suite.id().to_be_bytes());
        let label = |s: &[u8]| [s, &suffix].concat();
        let mut key = [0u8; 96];
        let mut salt = [0u8; 12];
        hkdf(&[], &base, &label(b"SFrame 1.0 Secret key "), &mut key);
        hkdf(&[], &base, &label(b"SFrame 1.0 Secret salt "), &mut salt);
        let mut enc = [0u8; 32];
        let mut auth = [0u8; 64];
        enc.copy_from_slice(&key[..32]);
        auth.copy_from_slice(&key[32..]);
        SFrameStream {
            enc,
            auth,
            salt,
            suite,
            kid,
            ctr: 0,
        }
    }

    /// `header || AES-CTR(plaintext) || tag`.
    pub fn protect(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let ctr = self.ctr;
        self.ctr += 1;
        let header = encode_header(self.kid, ctr);
        // nonce = salt XOR counter (BE, right-aligned).
        let mut iv = self.salt;
        for (d, c) in iv[4..].iter_mut().zip(ctr.to_be_bytes()) {
            *d ^= c;
        }
        let mut counter = [0u8; 16];
        counter[..12].copy_from_slice(&iv);
        let mut ct = plaintext.to_vec();
        Ctr128BE::<Aes256>::new((&self.enc).into(), (&counter).into()).apply_keystream(&mut ct);
        let nt = self.suite.tag_len();
        let mut mac = <Hmac<Sha512> as KeyInit>::new_from_slice(&self.auth).expect("HMAC");
        for len in [header.len(), ct.len(), nt] {
            mac.update(&(len as u64).to_be_bytes());
        }
        mac.update(&iv);
        mac.update(&header);
        mac.update(&ct);
        let tag = mac.finalize().into_bytes();
        let mut out = header;
        out.extend_from_slice(&ct);
        out.extend_from_slice(&tag[..nt]);
        out
    }
}

fn min_bytes(v: u64) -> Vec<u8> {
    let b = v.to_be_bytes();
    let skip = b.iter().take_while(|x| **x == 0).count().min(7);
    b[skip..].to_vec()
}

/// RFC 9605 4.3: config byte X|KKK|Y|CCC and extended KID/CTR.
fn encode_header(kid: u64, ctr: u64) -> Vec<u8> {
    let mut config = 0u8;
    let mut extra = Vec::new();
    if kid <= 7 {
        config |= (kid as u8) << 4;
    } else {
        let k = min_bytes(kid);
        config |= 0x80 | (((k.len() - 1) as u8) << 4);
        extra.extend(k);
    }
    if ctr <= 7 {
        config |= ctr as u8;
    } else {
        let c = min_bytes(ctr);
        config |= 0x08 | (c.len() - 1) as u8;
        extra.extend(c);
    }
    let mut h = vec![config];
    h.extend(extra);
    h
}

/// draft-ietf-avtcore-rtp-sframe: one descriptor byte (S=0x80, E=0x40) in front of each chunk
/// of the encrypted frame. Returns `(payload, marker)` per packet.
pub fn packetize(sealed: &[u8], max_payload: usize, marker: bool) -> Vec<(Vec<u8>, bool)> {
    let chunk = max_payload.saturating_sub(1).max(1);
    let n = sealed.len().div_ceil(chunk);
    sealed
        .chunks(chunk)
        .enumerate()
        .map(|(i, c)| {
            let last = i + 1 == n;
            let d = if i == 0 { 0x80 } else { 0 } | if last { 0x40 } else { 0 };
            let mut p = Vec::with_capacity(c.len() + 1);
            p.push(d);
            p.extend_from_slice(c);
            (p, marker && last)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Vectors generated with the reference code (sframe.ts, Node crypto) for key
    // 0x11*32, ssrc 0x01020304, kid 0x100.
    const VIDEO_PT: &str = "000000024e01aabbccdd0102030405060708090a0b0c0d0e0f1011";
    const VIDEO_CT3: &str =
        "93010085ec4594a9009032dff35fd5f7a5296b21a403a3a28f15cee5342312d93d0bbf2f151df622";
    const AUDIO_CT0: &str = "900100d1a54ce464c2e2";

    #[test]
    fn matches_reference_vectors() {
        let key = [0x11u8; 32];
        let mut v = SFrameStream::new(&key, SENDER_KID, 0x0102_0304, Suite::Video);
        let pt = hex::decode(VIDEO_PT).unwrap();
        for _ in 0..3 {
            v.protect(&pt); // advances the counter to 3
        }
        assert_eq!(hex::encode(v.protect(&pt)), VIDEO_CT3);
        let mut a = SFrameStream::new(&key, SENDER_KID, 0x0102_0304, Suite::Audio);
        assert_eq!(hex::encode(a.protect(&[0xf8, 0xff, 0xe1])), AUDIO_CT0);
    }

    #[test]
    fn header_encoding() {
        assert_eq!(encode_header(0x100, 3), [0x93, 0x01, 0x00]);
        assert_eq!(encode_header(0x100, 0x1234), [0x99, 0x01, 0x00, 0x12, 0x34]);
        assert_eq!(encode_header(2, 5), [0x25]);
    }

    #[test]
    fn packetize_marks_start_end_and_limits_size() {
        let data = vec![7u8; 4000];
        let p = packetize(&data, 1200, true);
        assert_eq!(p.len(), 4);
        assert!(p.iter().all(|(b, _)| b.len() <= 1200));
        assert_eq!(p[0].0[0], 0x80);
        assert_eq!(p[1].0[0], 0);
        assert_eq!(p[3].0[0], 0x40);
        assert_eq!(p.iter().filter(|(_, m)| *m).count(), 1);
        assert!(p[3].1);
        let joined: Vec<u8> = p.iter().flat_map(|(b, _)| b[1..].to_vec()).collect();
        assert_eq!(joined, data);
        let one = packetize(&[1, 2], 1200, false);
        assert_eq!(one[0].0, [0xc0, 1, 2]);
    }
}
