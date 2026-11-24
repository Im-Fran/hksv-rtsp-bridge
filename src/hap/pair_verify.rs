//! Pair Verify (HAP): accessory-side M1 -> M4; produces the session keys.

use anyhow::Result;
use ed25519_dalek::{Signature, Signer, Verifier};
use x25519_dalek::{X25519_BASEPOINT_BYTES, x25519};

use super::crypto::{AccessoryIdentity, Pairings, SessionKeys, hkdf_sha512, open_msg, seal_msg};
use super::tlv8::Tlv8;
use super::tlv8::{
    ERR_AUTHENTICATION, ERR_UNKNOWN, T_ENCRYPTED, T_ERROR, T_IDENTIFIER, T_PUBLIC_KEY, T_SIGNATURE,
    T_STATE,
};

struct Pending {
    acc_pub: [u8; 32],
    ctl_pub: [u8; 32],
    shared: [u8; 32],
    enc_key: [u8; 32],
}

#[derive(Default)]
pub struct PairVerify {
    pending: Option<Pending>,
    verified: Option<String>,
}

fn error_response(state: u8, code: u8) -> Vec<u8> {
    Tlv8::new()
        .push_u8(T_STATE, state)
        .push_u8(T_ERROR, code)
        .encode()
}

impl PairVerify {
    pub fn new() -> Self {
        Self::default()
    }

    /// ID of the authenticated controller after a successful M3.
    pub fn controller_id(&self) -> Option<&str> {
        self.verified.as_deref()
    }

    /// Returns the response and, on completing M3, the session keys.
    pub fn handle(
        &mut self,
        req: &[u8],
        id: &AccessoryIdentity,
        pairings: &dyn Pairings,
    ) -> Result<(Vec<u8>, Option<SessionKeys>)> {
        let tlv = Tlv8::parse(req)?;
        let state = tlv.get_u8(T_STATE)?.unwrap_or(0);
        let pending = self.pending.take();
        match (state, pending) {
            (1, _) => {
                let Some(ctl_pub) = tlv
                    .get(T_PUBLIC_KEY)
                    .and_then(|k| <[u8; 32]>::try_from(k).ok())
                else {
                    return Ok((error_response(2, ERR_UNKNOWN), None));
                };
                let secret: [u8; 32] = rand::random();
                let acc_pub = x25519(secret, X25519_BASEPOINT_BYTES);
                let shared = x25519(secret, ctl_pub);
                if shared == [0u8; 32] {
                    return Ok((error_response(2, ERR_UNKNOWN), None));
                }
                let enc_key = hkdf_sha512(
                    &shared,
                    b"Pair-Verify-Encrypt-Salt",
                    b"Pair-Verify-Encrypt-Info",
                );
                let info = [&acc_pub[..], id.device_id.as_bytes(), &ctl_pub[..]].concat();
                let sig = id.signing.sign(&info).to_bytes();
                let inner = Tlv8::new()
                    .push(T_IDENTIFIER, id.device_id.as_bytes())
                    .push(T_SIGNATURE, &sig)
                    .encode();
                let out = Tlv8::new()
                    .push_u8(T_STATE, 2)
                    .push(T_PUBLIC_KEY, &acc_pub)
                    .push(T_ENCRYPTED, &seal_msg(&enc_key, b"PV-Msg02", &inner))
                    .encode();
                self.pending = Some(Pending {
                    acc_pub,
                    ctl_pub,
                    shared,
                    enc_key,
                });
                Ok((out, None))
            }
            (3, Some(p)) => Ok(match m3(&tlv, &p, pairings) {
                Ok(ctl_id) => {
                    self.verified = Some(ctl_id);
                    (
                        Tlv8::new().push_u8(T_STATE, 4).encode(),
                        Some(SessionKeys::derive(p.shared)),
                    )
                }
                Err(code) => (error_response(4, code), None),
            }),
            _ => Ok((error_response(state.wrapping_add(1), ERR_UNKNOWN), None)),
        }
    }
}

fn m3(tlv: &Tlv8, p: &Pending, pairings: &dyn Pairings) -> Result<String, u8> {
    let data = tlv.get(T_ENCRYPTED).ok_or(ERR_UNKNOWN)?;
    let plain = open_msg(&p.enc_key, b"PV-Msg03", data).map_err(|_| ERR_AUTHENTICATION)?;
    let sub = Tlv8::parse(&plain).map_err(|_| ERR_UNKNOWN)?;
    let (Some(ctl_id), Some(sig)) = (sub.get(T_IDENTIFIER), sub.get(T_SIGNATURE)) else {
        return Err(ERR_UNKNOWN);
    };
    let ctl_id_str = std::str::from_utf8(ctl_id).map_err(|_| ERR_AUTHENTICATION)?;
    let ltpk = pairings.get(ctl_id_str).ok_or(ERR_AUTHENTICATION)?;
    let sig: [u8; 64] = sig.try_into().map_err(|_| ERR_AUTHENTICATION)?;
    let info = [&p.ctl_pub[..], ctl_id, &p.acc_pub[..]].concat();
    ltpk.verify(&info, &Signature::from_bytes(&sig))
        .map_err(|_| ERR_AUTHENTICATION)?;
    Ok(ctl_id_str.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hap::pair_setup::PairSetup;
    use crate::hap::test_controller::{Controller, MemPairings, accessory};

    const CODE: &str = "031-45-154";

    #[test]
    fn pair_verify_roundtrip() {
        let (acc, ctl) = (accessory(), Controller::new("controller-1"));
        let mut pairings = MemPairings::default();
        let ltpk = ctl
            .pair_setup(&mut PairSetup::new(), &acc, CODE, CODE, &mut pairings)
            .unwrap();
        let (acc_side, ctl_side) = ctl
            .pair_verify(&mut PairVerify::new(), &acc, &ltpk, &pairings)
            .unwrap();
        assert_eq!(acc_side.shared_secret, ctl_side.shared_secret);
        assert_eq!(acc_side.read, ctl_side.read);
        assert_eq!(acc_side.write, ctl_side.write);
        assert_ne!(acc_side.read, acc_side.write);
    }

    #[test]
    fn pair_verify_unknown_controller() {
        let (acc, ctl) = (accessory(), Controller::new("desconocido"));
        let err = ctl
            .pair_verify(
                &mut PairVerify::new(),
                &acc,
                &acc.signing.verifying_key(),
                &MemPairings::default(),
            )
            .err()
            .unwrap();
        assert!(err.to_string().contains("TLV error [2]"), "{err}");
    }
}
