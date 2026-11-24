//! Simulated HomeKit controller for tests (reusable by other modules).

use std::collections::HashMap;

use anyhow::{Result, anyhow, bail};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use num_bigint::BigUint;
use x25519_dalek::{X25519_BASEPOINT_BYTES, x25519};

use super::crypto::{AccessoryIdentity, Pairings, SessionKeys, hkdf_sha512, open_msg, seal_msg};
use super::pair_setup::PairSetup;
use super::srp;
use super::tlv8::Tlv8;
use super::tlv8::*;

#[derive(Default)]
pub(crate) struct MemPairings(pub HashMap<String, (VerifyingKey, bool)>);

impl Pairings for MemPairings {
    fn get(&self, id: &str) -> Option<VerifyingKey> {
        self.0.get(id).map(|(k, _)| *k)
    }
    fn add(&mut self, id: String, ltpk: VerifyingKey, admin: bool) -> Result<()> {
        self.0.insert(id, (ltpk, admin));
        Ok(())
    }
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

pub(crate) fn accessory() -> AccessoryIdentity {
    AccessoryIdentity {
        device_id: "AA:BB:CC:DD:EE:FF".into(),
        signing: SigningKey::from_bytes(&rand::random()),
    }
}

pub(crate) struct Controller {
    pub id: String,
    pub signing: SigningKey,
}

fn tlv_get(resp: &[u8], t: u8) -> Result<Vec<u8>> {
    let tlv = Tlv8::parse(resp)?;
    if let Some(e) = tlv.get(T_ERROR) {
        bail!("TLV error {e:?}");
    }
    tlv.get(t)
        .map(<[u8]>::to_vec)
        .ok_or_else(|| anyhow!("missing TLV {t}"))
}

impl Controller {
    pub fn new(id: &str) -> Self {
        Self {
            id: id.into(),
            signing: SigningKey::from_bytes(&rand::random()),
        }
    }

    /// Full Pair Setup against `setup`; returns the accessory's LTPK verified in M6.
    /// Client-side SRP path written separately from the server: S = (B - k g^x)^(a + u x).
    pub fn pair_setup(
        &self,
        setup: &mut PairSetup,
        acc: &AccessoryIdentity,
        server_code: &str,
        client_code: &str,
        pairings: &mut MemPairings,
    ) -> Result<VerifyingKey> {
        self.pair_setup_via(
            &mut |m| setup.handle(m, acc, server_code, pairings),
            &acc.device_id,
            client_code,
        )
    }

    /// Same as `pair_setup` but messages M1..M5 travel through `send` (e.g. HTTP).
    pub fn pair_setup_via(
        &self,
        send: &mut dyn FnMut(&[u8]) -> Result<Vec<u8>>,
        acc_device_id: &str,
        client_code: &str,
    ) -> Result<VerifyingKey> {
        let m1 = Tlv8::new()
            .push_u8(T_STATE, 1)
            .push_u8(T_METHOD, 0)
            .encode();
        let m2 = send(&m1)?;
        let salt = tlv_get(&m2, T_SALT)?;
        let b_bytes = tlv_get(&m2, T_PUBLIC_KEY)?;

        let (n, g) = (srp::n(), srp::g());
        let a_priv = BigUint::from_bytes_be(&rand::random::<[u8; 32]>());
        let a_pub = g.modpow(&a_priv, &n);
        let b_pub = BigUint::from_bytes_be(&b_bytes);
        let x = srp::x(&salt, client_code.as_bytes());
        let u = srp::u(&a_pub, &b_pub);
        let base = (&n + &b_pub - (srp::k() * g.modpow(&x, &n)) % &n) % &n;
        let s = base.modpow(&(&a_priv + u * &x), &n);
        let key = srp::hash(&[&s.to_bytes_be()]);
        let m1p = srp::m1(&salt, &a_pub, &b_pub, &key);

        let m3 = Tlv8::new()
            .push_u8(T_STATE, 3)
            .push(T_PUBLIC_KEY, &srp::pad(&a_pub))
            .push(T_PROOF, &m1p)
            .encode();
        let m4 = send(&m3)?;
        if tlv_get(&m4, T_PROOF)? != srp::m2(&a_pub, &m1p, &key) {
            bail!("server M2 does not match");
        }

        let enc_key = hkdf_sha512(&key, b"Pair-Setup-Encrypt-Salt", b"Pair-Setup-Encrypt-Info");
        let x_sign = hkdf_sha512(
            &key,
            b"Pair-Setup-Controller-Sign-Salt",
            b"Pair-Setup-Controller-Sign-Info",
        );
        let ltpk = self.signing.verifying_key().to_bytes();
        let info = [&x_sign[..], self.id.as_bytes(), &ltpk[..]].concat();
        let inner = Tlv8::new()
            .push(T_IDENTIFIER, self.id.as_bytes())
            .push(T_PUBLIC_KEY, &ltpk)
            .push(T_SIGNATURE, &self.signing.sign(&info).to_bytes())
            .encode();
        let m5 = Tlv8::new()
            .push_u8(T_STATE, 5)
            .push(T_ENCRYPTED, &seal_msg(&enc_key, b"PS-Msg05", &inner))
            .encode();
        let m6 = send(&m5)?;

        let plain = open_msg(&enc_key, b"PS-Msg06", &tlv_get(&m6, T_ENCRYPTED)?)?;
        let sub = Tlv8::parse(&plain)?;
        let acc_id = sub.get(T_IDENTIFIER).ok_or_else(|| anyhow!("no id"))?;
        let acc_ltpk: [u8; 32] = sub
            .get(T_PUBLIC_KEY)
            .ok_or_else(|| anyhow!("no ltpk"))?
            .try_into()?;
        let sig: [u8; 64] = sub
            .get(T_SIGNATURE)
            .ok_or_else(|| anyhow!("no signature"))?
            .try_into()?;
        let acc_x = hkdf_sha512(
            &key,
            b"Pair-Setup-Accessory-Sign-Salt",
            b"Pair-Setup-Accessory-Sign-Info",
        );
        let info = [&acc_x[..], acc_id, &acc_ltpk[..]].concat();
        let vk = VerifyingKey::from_bytes(&acc_ltpk)?;
        vk.verify(&info, &Signature::from_bytes(&sig))?;
        if acc_id != acc_device_id.as_bytes() {
            bail!("accessory id differs");
        }
        Ok(vk)
    }

    /// Full Pair Verify; returns the session keys as seen by the controller.
    pub fn pair_verify(
        &self,
        verify: &mut super::pair_verify::PairVerify,
        acc: &AccessoryIdentity,
        acc_ltpk: &VerifyingKey,
        pairings: &MemPairings,
    ) -> Result<(SessionKeys, SessionKeys)> {
        let mut keys = None;
        let ctl = self.pair_verify_via(
            &mut |m| {
                let (resp, k) = verify.handle(m, acc, pairings)?;
                if k.is_some() {
                    keys = k;
                }
                Ok(resp)
            },
            acc_ltpk,
        )?;
        let keys = keys.ok_or_else(|| anyhow!("accessory did not deliver keys"))?;
        Ok((keys, ctl))
    }

    /// Pair Verify via `send`; returns the keys as seen by the controller. Fails if the
    /// accessory replies with an error in M4.
    pub fn pair_verify_via(
        &self,
        send: &mut dyn FnMut(&[u8]) -> Result<Vec<u8>>,
        acc_ltpk: &VerifyingKey,
    ) -> Result<SessionKeys> {
        let secret: [u8; 32] = rand::random();
        let ctl_pub = x25519(secret, X25519_BASEPOINT_BYTES);
        let m1 = Tlv8::new()
            .push_u8(T_STATE, 1)
            .push(T_PUBLIC_KEY, &ctl_pub)
            .encode();
        let m2 = send(&m1)?;
        let acc_pub: [u8; 32] = tlv_get(&m2, T_PUBLIC_KEY)?
            .try_into()
            .map_err(|_| anyhow!("pk"))?;
        let shared = x25519(secret, acc_pub);
        let enc_key = hkdf_sha512(
            &shared,
            b"Pair-Verify-Encrypt-Salt",
            b"Pair-Verify-Encrypt-Info",
        );
        let plain = open_msg(&enc_key, b"PV-Msg02", &tlv_get(&m2, T_ENCRYPTED)?)?;
        let sub = Tlv8::parse(&plain)?;
        let acc_id = sub.get(T_IDENTIFIER).ok_or_else(|| anyhow!("no id"))?;
        let sig: [u8; 64] = sub
            .get(T_SIGNATURE)
            .ok_or_else(|| anyhow!("no signature"))?
            .try_into()?;
        let info = [&acc_pub[..], acc_id, &ctl_pub[..]].concat();
        acc_ltpk.verify(&info, &Signature::from_bytes(&sig))?;

        let info = [&ctl_pub[..], self.id.as_bytes(), &acc_pub[..]].concat();
        let inner = Tlv8::new()
            .push(T_IDENTIFIER, self.id.as_bytes())
            .push(T_SIGNATURE, &self.signing.sign(&info).to_bytes())
            .encode();
        let m3 = Tlv8::new()
            .push_u8(T_STATE, 3)
            .push(T_ENCRYPTED, &seal_msg(&enc_key, b"PV-Msg03", &inner))
            .encode();
        let m4 = send(&m3)?;
        tlv_get(&m4, T_STATE)?;
        Ok(SessionKeys::derive(shared))
    }
}
