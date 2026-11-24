//! Cryptographic primitives for HAP: HKDF-SHA512, ChaCha20-Poly1305 AEAD, session keys and
//! per-frame encryption, plus the accessory identity and the pairings trait.

use anyhow::{Result, anyhow, bail};
use bytes::{Buf, BytesMut};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use ed25519_dalek::{SigningKey, VerifyingKey};
use hkdf::Hkdf;
use sha2::Sha512;

/// Long-term identity of the accessory.
pub struct AccessoryIdentity {
    /// "AA:BB:CC:DD:EE:FF"
    pub device_id: String,
    pub signing: SigningKey,
}

/// Store of paired controllers (implemented in Task 5).
pub trait Pairings {
    fn get(&self, id: &str) -> Option<VerifyingKey>;
    fn add(&mut self, id: String, ltpk: VerifyingKey, admin: bool) -> Result<()>;
    fn is_empty(&self) -> bool;
}

/// Session keys derived in pair-verify.
pub struct SessionKeys {
    pub shared_secret: [u8; 32],
    /// accessory -> controller (the accessory encrypts with this)
    pub read: [u8; 32],
    /// controller -> accessory (the accessory decrypts with this)
    pub write: [u8; 32],
}

pub fn hkdf_sha512(ikm: &[u8], salt: &[u8], info: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    Hkdf::<Sha512>::new(Some(salt), ikm)
        .expand(info, &mut out)
        .expect("32 bytes is a valid length for HKDF-SHA512");
    out
}

impl SessionKeys {
    pub fn derive(shared_secret: [u8; 32]) -> Self {
        Self {
            shared_secret,
            read: hkdf_sha512(
                &shared_secret,
                b"Control-Salt",
                b"Control-Read-Encryption-Key",
            ),
            write: hkdf_sha512(
                &shared_secret,
                b"Control-Salt",
                b"Control-Write-Encryption-Key",
            ),
        }
    }
}

fn nonce_label(label: &[u8; 8]) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(label);
    n
}

fn cipher(key: &[u8; 32]) -> ChaCha20Poly1305 {
    ChaCha20Poly1305::new(key.into())
}

pub(crate) fn seal_raw(key: &[u8; 32], nonce: [u8; 12], aad: &[u8], plain: &[u8]) -> Vec<u8> {
    cipher(key)
        .encrypt(&Nonce::from(nonce), Payload { msg: plain, aad })
        .expect("ChaCha20-Poly1305 encryption does not fail")
}

pub(crate) fn open_raw(
    key: &[u8; 32],
    nonce: [u8; 12],
    aad: &[u8],
    data: &[u8],
) -> Result<Vec<u8>> {
    cipher(key)
        .decrypt(&Nonce::from(nonce), Payload { msg: data, aad })
        .map_err(|_| anyhow!("AEAD authentication failure"))
}

/// Encrypts a pairing message with a nonce of "4 zeros + label" (e.g. `b"PS-Msg05"`).
pub fn seal_msg(key: &[u8; 32], label: &[u8; 8], plain: &[u8]) -> Vec<u8> {
    seal_raw(key, nonce_label(label), &[], plain)
}

pub fn open_msg(key: &[u8; 32], label: &[u8; 8], data: &[u8]) -> Result<Vec<u8>> {
    open_raw(key, nonce_label(label), &[], data)
}

/// Maximum data per HAP session frame.
pub const MAX_FRAME: usize = 1024;
const TAG: usize = 16;

/// Frame encryption for the HAP session (HTTP over encrypted TCP).
pub struct FrameCipher {
    encrypt_key: [u8; 32],
    decrypt_key: [u8; 32],
    encrypt_counter: u64,
    decrypt_counter: u64,
}

pub(crate) fn counter_nonce(c: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&c.to_le_bytes());
    n
}

impl FrameCipher {
    pub fn new(encrypt_key: [u8; 32], decrypt_key: [u8; 32]) -> Self {
        Self {
            encrypt_key,
            decrypt_key,
            encrypt_counter: 0,
            decrypt_counter: 0,
        }
    }

    /// Splits `plain` into frames of up to 1024 bytes: `len(2 LE) | ciphertext | tag`.
    pub fn encrypt_frames(&mut self, plain: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(plain.len() + (plain.len() / MAX_FRAME + 1) * (2 + TAG));
        for chunk in plain.chunks(MAX_FRAME) {
            let aad = (chunk.len() as u16).to_le_bytes();
            let ct = seal_raw(
                &self.encrypt_key,
                counter_nonce(self.encrypt_counter),
                &aad,
                chunk,
            );
            self.encrypt_counter += 1;
            out.extend_from_slice(&aad);
            out.extend_from_slice(&ct);
        }
        out
    }

    /// Decrypts one complete frame from the start of `buf` and consumes it. `Ok(None)` if bytes are missing.
    pub fn decrypt(&mut self, buf: &mut BytesMut) -> Result<Option<Vec<u8>>> {
        if buf.len() < 2 {
            return Ok(None);
        }
        let len = u16::from_le_bytes([buf[0], buf[1]]) as usize;
        if len > MAX_FRAME {
            bail!("HAP frame of {len} bytes exceeds {MAX_FRAME}");
        }
        if buf.len() < 2 + len + TAG {
            return Ok(None);
        }
        let plain = open_raw(
            &self.decrypt_key,
            counter_nonce(self.decrypt_counter),
            &buf[..2],
            &buf[2..2 + len + TAG],
        )?;
        self.decrypt_counter += 1;
        buf.advance(2 + len + TAG);
        Ok(Some(plain))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> (FrameCipher, FrameCipher) {
        let keys = SessionKeys::derive([7u8; 32]);
        (
            FrameCipher::new(keys.read, keys.write),
            FrameCipher::new(keys.write, keys.read),
        )
    }

    /// HKDF-SHA512 vector computed in Python (hmac/hashlib), independent of `derive`.
    #[test]
    fn session_key_direction_vector() {
        let hex = |b: [u8; 32]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        let k = SessionKeys::derive([7u8; 32]);
        assert_eq!(
            hex(k.read),
            "8019e5f55c498dc89918103b376c0cdb3015a20d8a881b7616ad76d206087df5"
        );
        assert_eq!(
            hex(k.write),
            "e1df5f5fd4b585d4fc0233b6139aabcedbf0b8b802a7cd220f489363191c79eb"
        );
    }

    #[test]
    fn frame_cipher_roundtrip_2500_bytes() {
        let (mut acc, mut ctl) = pair();
        let plain: Vec<u8> = (0..2500u32).map(|i| i as u8).collect();
        let wire = acc.encrypt_frames(&plain);
        assert_eq!(wire.len(), 2500 + 3 * 18);
        assert_eq!(u16::from_le_bytes([wire[0], wire[1]]), 1024);
        let mut buf = BytesMut::from(&wire[..]);
        let mut out = Vec::new();
        let mut sizes = Vec::new();
        while let Some(p) = ctl.decrypt(&mut buf).unwrap() {
            sizes.push(p.len());
            out.extend(p);
        }
        assert_eq!(sizes, [1024, 1024, 452]);
        assert_eq!(out, plain);
        assert!(buf.is_empty());
    }

    #[test]
    fn frame_cipher_partial_and_tampered() {
        let (mut acc, mut ctl) = pair();
        let wire = acc.encrypt_frames(b"hola");
        let mut buf = BytesMut::from(&wire[..wire.len() - 1]);
        assert!(ctl.decrypt(&mut buf).unwrap().is_none());
        let mut bad = wire.clone();
        bad[3] ^= 1;
        assert!(ctl.decrypt(&mut BytesMut::from(&bad[..])).is_err());
        let mut hdr = wire.clone();
        hdr[0] ^= 1; // the length is AAD
        hdr.extend([0u8; 16]);
        assert!(ctl.decrypt(&mut BytesMut::from(&hdr[..])).is_err());
        let mut big = BytesMut::from(&[0xFF, 0xFF][..]);
        assert!(ctl.decrypt(&mut big).is_err());
    }

    #[test]
    fn frame_counters_must_stay_in_sync() {
        let (mut acc, mut ctl) = pair();
        let (w1, w2) = (acc.encrypt_frames(b"uno"), acc.encrypt_frames(b"dos"));
        assert!(ctl.decrypt(&mut BytesMut::from(&w2[..])).is_err());
        assert_eq!(
            ctl.decrypt(&mut BytesMut::from(&w1[..])).unwrap().unwrap(),
            b"uno"
        );
    }
}
