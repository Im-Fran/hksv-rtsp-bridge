//! Our own SRTCP Sender Reports. ffmpeg's SRs map RTP ts -> NTP with their own clock, which
//! no longer matches when packets actually leave (video pacing 2 ms + 250 ms, audio 20 ms with
//! a buffer): measured, video arrived 5-143 ms after what its SR said and audio 92 ms before,
//! a variable A/V offset of ~166 ms that the receiver uses to align (and cuts the audio when
//! resyncing). The relay discards ffmpeg's RTCP and emits SRs with the real send clock.
use aes::Aes128;
use ctr::Ctr128BE;
use ctr::cipher::{BlockCipherEncrypt, KeyInit, KeyIvInit, StreamCipher};
use hmac::{Hmac, Mac};
use sha1::Sha1;

use crate::camera::setup_endpoints::SrtpParams;

/// Counters for the outgoing RTP flow (what the relay actually sent).
#[derive(Default)]
pub(super) struct Sender {
    pub ssrc: u32,
    pub packets: u32,
    pub octets: u32,
    pub last_ts: u32,
    pub last_at: Option<std::time::Instant>,
}

impl Sender {
    /// Records an outgoing SRTP datagram (12-byte header + payload + 10-byte tag).
    pub fn sent(&mut self, p: &[u8]) {
        if p.len() < 22 {
            return;
        }
        self.ssrc = u32::from_be_bytes([p[8], p[9], p[10], p[11]]);
        self.last_ts = u32::from_be_bytes([p[4], p[5], p[6], p[7]]);
        self.last_at = Some(std::time::Instant::now());
        self.packets = self.packets.wrapping_add(1);
        self.octets = self.octets.wrapping_add((p.len() - 22) as u32);
    }
}

pub(super) struct Srtcp {
    key: [u8; 16],
    salt: [u8; 14],
    auth: [u8; 20],
    index: u32,
    hz: u32,
}

/// RFC 3711 4.3 key derivation (kdr = 0): AES-CM over (salt ^ label) with a block counter.
fn kdf(key: &[u8; 16], salt: &[u8; 14], label: u8, out: &mut [u8]) {
    let c = Aes128::new(key.into());
    for (i, chunk) in out.chunks_mut(16).enumerate() {
        let mut iv = [0u8; 16];
        iv[..14].copy_from_slice(salt);
        iv[7] ^= label;
        iv[14..].copy_from_slice(&(i as u16).to_be_bytes());
        let mut b = iv.into();
        c.encrypt_block(&mut b);
        chunk.copy_from_slice(&b[..chunk.len()]);
    }
}

impl Srtcp {
    pub fn new(p: &SrtpParams, hz: u32) -> Srtcp {
        let (mut key, mut salt, mut auth) = ([0; 16], [0; 14], [0; 20]);
        kdf(&p.key, &p.salt, 3, &mut key);
        kdf(&p.key, &p.salt, 5, &mut salt);
        kdf(&p.key, &p.salt, 4, &mut auth);
        Srtcp {
            key,
            salt,
            auth,
            index: 0,
            hz,
        }
    }

    /// Authentication tag (10 B) computed for an SRTCP packet that does not have one yet.
    pub fn tag(&self, pkt: &[u8]) -> [u8; 10] {
        let mut m = <Hmac<Sha1> as KeyInit>::new_from_slice(&self.auth).expect("HMAC key");
        m.update(pkt);
        let full = m.finalize().into_bytes();
        full[..10].try_into().unwrap()
    }

    /// SR + SDES(CNAME), encrypted and authenticated. The RTP ts is extrapolated from the last packet
    /// sent, so that (NTP now <-> ts) stays consistent with the real send time.
    pub fn sender_report(&mut self, s: &Sender) -> Option<Vec<u8>> {
        let last = s.last_at?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?;
        let ts = s
            .last_ts
            .wrapping_add((last.elapsed().as_secs_f64() * f64::from(self.hz)) as u32);
        let mut p = vec![0x80, 200, 0, 6];
        p.extend(s.ssrc.to_be_bytes());
        p.extend(((now.as_secs() + 2_208_988_800) as u32).to_be_bytes());
        p.extend(
            ((u64::from(now.subsec_nanos()) << 32) / 1_000_000_000).to_be_bytes()[4..].to_vec(),
        );
        p.extend(ts.to_be_bytes());
        p.extend(s.packets.to_be_bytes());
        p.extend(s.octets.to_be_bytes());
        // SDES with CNAME "dvr" (RFC 3550 requires the CNAME in every compound packet).
        p.extend([0x81, 202, 0, 3]);
        p.extend(s.ssrc.to_be_bytes());
        p.extend([1, 3, b'd', b'v', b'r', 0, 0, 0]);
        // Encryption: IV = salt<<16 ^ ssrc<<64 ^ index<<16.
        self.index = (self.index + 1) & 0x7fff_ffff;
        let mut iv = [0u8; 16];
        iv[..14].copy_from_slice(&self.salt);
        for (i, b) in s.ssrc.to_be_bytes().iter().enumerate() {
            iv[4 + i] ^= b;
        }
        for (i, b) in self.index.to_be_bytes().iter().enumerate() {
            iv[10 + i] ^= b;
        }
        Ctr128BE::<Aes128>::new((&self.key).into(), (&iv).into()).apply_keystream(&mut p[8..]);
        p.extend((self.index | 0x8000_0000).to_be_bytes());
        let tag = self.tag(&p);
        p.extend(tag);
        Some(p)
    }
}
