//! Pair Setup (HAP, method 0, no MFi): accessory-side state machine, M1 -> M6.

use anyhow::Result;
use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};

use super::crypto::{AccessoryIdentity, Pairings, hkdf_sha512, open_msg, seal_msg};
use super::srp::{SrpServer, SrpSession};
use super::tlv8::{
    ERR_AUTHENTICATION, ERR_UNAVAILABLE, ERR_UNKNOWN, T_ENCRYPTED, T_ERROR, T_IDENTIFIER, T_PROOF,
    T_PUBLIC_KEY, T_SALT, T_SIGNATURE, T_STATE, Tlv8,
};

fn error_response(state: u8, code: u8) -> Vec<u8> {
    Tlv8::new()
        .push_u8(T_STATE, state)
        .push_u8(T_ERROR, code)
        .encode()
}

#[derive(Default)]
enum Stage {
    #[default]
    Idle,
    /// M2 sent, waiting for M3.
    AwaitM3(SrpServer),
    /// M4 sent, waiting for M5.
    AwaitM5(Box<SrpSession>),
}

#[derive(Default)]
pub struct PairSetup {
    stage: Stage,
}

impl PairSetup {
    pub fn new() -> Self {
        Self::default()
    }

    /// Processes a message from the controller. Protocol failures are answered with an error TLV
    /// (`Ok`) and reset the state machine; `Err` is only for unreadable input.
    pub fn handle(
        &mut self,
        req: &[u8],
        id: &AccessoryIdentity,
        setup_code: &str,
        pairings: &mut dyn Pairings,
    ) -> Result<Vec<u8>> {
        let tlv = Tlv8::parse(req)?;
        let state = tlv.get_u8(T_STATE)?.unwrap_or(0);
        let stage = std::mem::take(&mut self.stage);
        match (state, stage) {
            (1, _) => {
                if !pairings.is_empty() {
                    return Ok(error_response(2, ERR_UNAVAILABLE));
                }
                let srp = SrpServer::new(setup_code.as_bytes());
                let out = Tlv8::new()
                    .push_u8(T_STATE, 2)
                    .push(T_PUBLIC_KEY, &srp.public_b())
                    .push(T_SALT, srp.salt())
                    .encode();
                self.stage = Stage::AwaitM3(srp);
                Ok(out)
            }
            (3, Stage::AwaitM3(srp)) => {
                let (Some(a), Some(proof)) = (tlv.get(T_PUBLIC_KEY), tlv.get(T_PROOF)) else {
                    return Ok(error_response(4, ERR_UNKNOWN));
                };
                match srp.verify(a, proof) {
                    Ok(session) => {
                        let out = Tlv8::new()
                            .push_u8(T_STATE, 4)
                            .push(T_PROOF, &session.m2)
                            .encode();
                        self.stage = Stage::AwaitM5(Box::new(session));
                        Ok(out)
                    }
                    Err(_) => Ok(error_response(4, ERR_AUTHENTICATION)),
                }
            }
            (5, Stage::AwaitM5(session)) => {
                Ok(m5_m6(&tlv, &session, id, pairings)
                    .unwrap_or_else(|code| error_response(6, code)))
            }
            _ => Ok(error_response(state.wrapping_add(1), ERR_UNKNOWN)),
        }
    }
}

/// M5 -> M6. `Err(code)` is the HAP error code to respond with.
fn m5_m6(
    tlv: &Tlv8,
    session: &SrpSession,
    id: &AccessoryIdentity,
    pairings: &mut dyn Pairings,
) -> Result<Vec<u8>, u8> {
    let k = &session.key;
    let enc_key = hkdf_sha512(k, b"Pair-Setup-Encrypt-Salt", b"Pair-Setup-Encrypt-Info");
    let data = tlv.get(T_ENCRYPTED).ok_or(ERR_UNKNOWN)?;
    let plain = open_msg(&enc_key, b"PS-Msg05", data).map_err(|_| ERR_AUTHENTICATION)?;
    let sub = Tlv8::parse(&plain).map_err(|_| ERR_UNKNOWN)?;
    let (Some(ctl_id), Some(ltpk), Some(sig)) = (
        sub.get(T_IDENTIFIER),
        sub.get(T_PUBLIC_KEY),
        sub.get(T_SIGNATURE),
    ) else {
        return Err(ERR_UNKNOWN);
    };
    let ltpk: [u8; 32] = ltpk.try_into().map_err(|_| ERR_AUTHENTICATION)?;
    let sig: [u8; 64] = sig.try_into().map_err(|_| ERR_AUTHENTICATION)?;
    let ctl_pub = VerifyingKey::from_bytes(&ltpk).map_err(|_| ERR_AUTHENTICATION)?;
    let ctl_id_str = std::str::from_utf8(ctl_id).map_err(|_| ERR_UNKNOWN)?;

    let ctl_x = hkdf_sha512(
        k,
        b"Pair-Setup-Controller-Sign-Salt",
        b"Pair-Setup-Controller-Sign-Info",
    );
    let info = [&ctl_x[..], ctl_id, &ltpk[..]].concat();
    ctl_pub
        .verify(&info, &Signature::from_bytes(&sig))
        .map_err(|_| ERR_AUTHENTICATION)?;

    // HAP: the controller performing Pair Setup is always admin; iOS does not send T_PERMISSIONS in M5.
    pairings
        .add(ctl_id_str.to_owned(), ctl_pub, true)
        .map_err(|_| ERR_UNKNOWN)?;

    let acc_x = hkdf_sha512(
        k,
        b"Pair-Setup-Accessory-Sign-Salt",
        b"Pair-Setup-Accessory-Sign-Info",
    );
    let acc_ltpk = id.signing.verifying_key().to_bytes();
    let info = [&acc_x[..], id.device_id.as_bytes(), &acc_ltpk[..]].concat();
    let signature = id.signing.sign(&info).to_bytes();
    let inner = Tlv8::new()
        .push(T_IDENTIFIER, id.device_id.as_bytes())
        .push(T_PUBLIC_KEY, &acc_ltpk)
        .push(T_SIGNATURE, &signature)
        .encode();
    Ok(Tlv8::new()
        .push_u8(T_STATE, 6)
        .push(T_ENCRYPTED, &seal_msg(&enc_key, b"PS-Msg06", &inner))
        .encode())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hap::test_controller::{Controller, MemPairings, accessory};
    use crate::hap::tlv8::T_METHOD;

    const CODE: &str = "031-45-154";

    #[test]
    fn pair_setup_full_exchange() {
        let (acc, ctl) = (accessory(), Controller::new("controller-1"));
        let mut pairings = MemPairings::default();
        let ltpk = ctl
            .pair_setup(&mut PairSetup::new(), &acc, CODE, CODE, &mut pairings)
            .unwrap();
        assert_eq!(ltpk, acc.signing.verifying_key());
        // iOS does not send T_PERMISSIONS in M5 (nor does test_controller): it must still end up as admin.
        let (stored, admin) = pairings.0["controller-1"];
        assert_eq!(stored, ctl.signing.verifying_key());
        assert!(admin);
    }

    #[test]
    fn pair_setup_wrong_code() {
        let (acc, ctl) = (accessory(), Controller::new("controller-1"));
        let mut pairings = MemPairings::default();
        let mut setup = PairSetup::new();
        let err = ctl
            .pair_setup(&mut setup, &acc, CODE, "000-00-000", &mut pairings)
            .unwrap_err();
        assert!(err.to_string().contains("TLV error [2]"), "{err}");
        assert!(pairings.0.is_empty());
    }

    #[test]
    fn pair_setup_when_paired_is_unavailable() {
        let (acc, ctl) = (accessory(), Controller::new("controller-1"));
        let mut pairings = MemPairings::default();
        pairings
            .add("other".into(), ctl.signing.verifying_key(), true)
            .unwrap();
        let m1 = Tlv8::new()
            .push_u8(T_STATE, 1)
            .push_u8(T_METHOD, 0)
            .encode();
        let resp = PairSetup::new()
            .handle(&m1, &acc, CODE, &mut pairings)
            .unwrap();
        let tlv = Tlv8::parse(&resp).unwrap();
        assert_eq!(tlv.get_u8(T_STATE).unwrap(), Some(2));
        assert_eq!(tlv.get_u8(T_ERROR).unwrap(), Some(ERR_UNAVAILABLE));
    }
}
