//! HAP's SRP-6a (RFC 5054, 3072-bit group, SHA-512), server side.
//!
//! Implemented by hand because the `srp` 0.6 crate defines M1 = H(A, B, K) and u without padding,
//! which is incompatible with iOS. Definitions (same as go2rtc/tadglines, tested with iOS):
//! k = H(N | PAD(g)), x = H(s | H(I ":" P)), u = H(PAD(A) | PAD(B)), K = H(S), S without leading zeros,
//! M1 = H(H(N) xor H(g) | H(I) | s | A | B | K) with A and B without leading zeros,
//! M2 = H(A | M1 | K).

use anyhow::{Result, bail};
use num_bigint::BigUint;
use sha2::{Digest, Sha512};
use subtle::ConstantTimeEq;

pub const USERNAME: &[u8] = b"Pair-Setup";
pub const N_LEN: usize = 384;
const N_HEX: &str = concat!(
    "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74",
    "020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f1437",
    "4fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7ed",
    "ee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf05",
    "98da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb",
    "9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3b",
    "e39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf695581718",
    "3995497cea956ae515d2261898fa051015728e5a8aaac42dad33170d04507a33",
    "a85521abdf1cba64ecfb850458dbef0a8aea71575d060c7db3970f85a6e1e4c7",
    "abf5ae8cdb0933d71e8c94e04a25619dcee3d2261ad2ee6bf12ffa06d98a0864",
    "d87602733ec86a64521f2b18177b200cbbe117577a615d6c770988c0bad946e2",
    "08e24fa074e5ab3143db5bfce0fd108e4b82d120a93ad2caffffffffffffffff",
);

pub fn n() -> BigUint {
    BigUint::parse_bytes(N_HEX.as_bytes(), 16).expect("valid N hex")
}

pub fn g() -> BigUint {
    BigUint::from(5u8)
}

pub fn hash(parts: &[&[u8]]) -> [u8; 64] {
    let mut h = Sha512::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// PAD(x): big-endian, left-padded with zeros up to `N_LEN`.
pub fn pad(x: &BigUint) -> Vec<u8> {
    let b = x.to_bytes_be();
    let mut out = vec![0u8; N_LEN.saturating_sub(b.len())];
    out.extend_from_slice(&b);
    out
}

pub fn k() -> BigUint {
    BigUint::from_bytes_be(&hash(&[&n().to_bytes_be(), &pad(&g())]))
}

pub fn x(salt: &[u8], password: &[u8]) -> BigUint {
    let inner = hash(&[USERNAME, b":", password]);
    BigUint::from_bytes_be(&hash(&[salt, &inner]))
}

pub fn u(a: &BigUint, b: &BigUint) -> BigUint {
    BigUint::from_bytes_be(&hash(&[&pad(a), &pad(b)]))
}

/// M1 = H(H(N) xor H(g) | H(I) | s | A | B | K)
pub fn m1(salt: &[u8], a: &BigUint, b: &BigUint, key: &[u8; 64]) -> [u8; 64] {
    let hn = hash(&[&n().to_bytes_be()]);
    let hg = hash(&[&g().to_bytes_be()]);
    let mut xor = [0u8; 64];
    for i in 0..64 {
        xor[i] = hn[i] ^ hg[i];
    }
    hash(&[
        &xor,
        &hash(&[USERNAME]),
        salt,
        &a.to_bytes_be(),
        &b.to_bytes_be(),
        key,
    ])
}

/// M2 = H(A | M1 | K)
pub fn m2(a: &BigUint, m1: &[u8; 64], key: &[u8; 64]) -> [u8; 64] {
    hash(&[&a.to_bytes_be(), m1, key])
}

pub struct SrpServer {
    salt: [u8; 16],
    v: BigUint,
    b_pub: BigUint,
    b_priv: BigUint,
}

pub struct SrpSession {
    pub key: [u8; 64],
    pub m2: [u8; 64],
}

impl SrpServer {
    pub fn new(password: &[u8]) -> Self {
        Self::with_secrets(password, rand::random(), &rand::random::<[u8; 32]>())
    }

    pub fn with_secrets(password: &[u8], salt: [u8; 16], b: &[u8]) -> Self {
        let (n, g) = (n(), g());
        let v = g.modpow(&x(&salt, password), &n);
        let b_priv = BigUint::from_bytes_be(b);
        let b_pub = (k() * &v + g.modpow(&b_priv, &n)) % &n;
        Self {
            salt,
            v,
            b_pub,
            b_priv,
        }
    }

    pub fn salt(&self) -> &[u8; 16] {
        &self.salt
    }

    /// B padded to 384 bytes (as the controller expects).
    pub fn public_b(&self) -> Vec<u8> {
        pad(&self.b_pub)
    }

    /// Validates the controller's M1; returns K and M2 only if the proof is correct.
    pub fn verify(&self, a_bytes: &[u8], m1_client: &[u8]) -> Result<SrpSession> {
        let n = n();
        let a = BigUint::from_bytes_be(a_bytes);
        if a >= n || &a % &n == BigUint::default() {
            bail!("SRP: invalid A");
        }
        let u = u(&a, &self.b_pub);
        let base = &a * self.v.modpow(&u, &n) % &n;
        if base <= BigUint::from(1u8) || base == &n - 1u8 {
            bail!("SRP: invalid A·v^u");
        }
        let s = base.modpow(&self.b_priv, &n);
        let key = hash(&[&s.to_bytes_be()]);
        let expected = m1(&self.salt, &a, &self.b_pub, &key);
        if !bool::from(expected.ct_eq(m1_client)) {
            bail!("SRP: incorrect M1 proof");
        }
        Ok(SrpSession {
            key,
            m2: m2(&a, &expected, &key),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// Vector generated with an independent Python implementation (hashlib + pow),
    /// following the go2rtc/tadglines definitions.
    #[test]
    fn matches_independent_python_vector() {
        let server =
            SrpServer::with_secrets(b"031-45-154", core::array::from_fn(|i| i as u8), &[7; 32]);
        let b = server.public_b();
        assert_eq!(&hex(&b)[..32], "36309e78ff6254a0df63d0961cb0dc53");
        assert_eq!(&hex(&b)[b.len() * 2 - 16..], "7967e58ddb4662cd");

        let a = BigUint::from_bytes_be(&[9; 32]);
        let a_pub = g().modpow(&a, &n());
        assert_eq!(&hex(&pad(&a_pub))[..32], "8b99a0993389833d59055d2fac955f51");
        // The reference client computed M1 with S = (B - k g^x)^(a + u x).
        let b_pub = BigUint::from_bytes_be(&b);
        let xx = x(server.salt(), b"031-45-154");
        let base = (&n() + &b_pub - (k() * g().modpow(&xx, &n())) % n()) % n();
        let s = base.modpow(&(&a + u(&a_pub, &b_pub) * &xx), &n());
        let key = hash(&[&s.to_bytes_be()]);
        assert_eq!(
            hex(&key),
            "e8a9b6a771a8f2a32a46b54432ad2980760b5a083f4964e857399ad68bfa84ecca5fd92b54af2e51d26d5bf32c0c8326117b63fa981ee43dced59a60aae48210"
        );
        let m1v = m1(server.salt(), &a_pub, &b_pub, &key);
        assert_eq!(
            hex(&m1v),
            "3f2ac4be5aadde7ef4aa8d27caf87ffab86aacec31fd6e591936132c2c871c094ea27a09806689965863c5f00527004049ed5077c4743c933d63ef093ff0ad71"
        );
        let sess = server.verify(&pad(&a_pub), &m1v).unwrap();
        assert_eq!(sess.key, key);
        assert_eq!(
            hex(&sess.m2),
            "291920fc07d5d3d2a0d08aaa027d6fb3947cdf8889818c62fddb8f90f770c2adb7c8c793dbabc28cd78da7680ed4c0d74249b960b75bbf4df6c4b42d5dd8ce3f"
        );
        assert!(server.verify(&pad(&a_pub), &[0; 64]).is_err());
        assert!(server.verify(&[0; 384], &m1v).is_err());
        assert!(server.verify(&n().to_bytes_be(), &m1v).is_err()); // A = N
        assert!(server.verify(&(n() + 1u8).to_bytes_be(), &m1v).is_err()); // A > N
        assert!(server.verify(&[1], &m1v).is_err()); // A = 1 -> base = 1
    }
}
