//! TLV for Setup Endpoints (118): controller request and accessory response.
//! Same format as classic HAP (verified against a real iOS 27 capture).

use std::net::IpAddr;

use anyhow::{Context, Result, anyhow, bail, ensure};

use crate::hap::tlv8::Tlv8;

#[derive(Clone, PartialEq, Eq)]
pub struct SrtpParams {
    pub key: [u8; 16],
    pub salt: [u8; 14],
}

// Never print keys to the logs.
impl std::fmt::Debug for SrtpParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SrtpParams(..)")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EndpointRequest {
    pub session_id: [u8; 16],
    pub addr: IpAddr,
    pub video_port: u16,
    pub audio_port: u16,
    pub video_srtp: SrtpParams,
    pub audio_srtp: SrtpParams,
}

/// 0 = AES_CM_128_HMAC_SHA1_80, the only one we offer in Supported RTP Configuration.
const SUITE_80: u8 = 0;

fn parse_srtp(tlv: &[u8]) -> Result<SrtpParams> {
    let t = Tlv8::parse(tlv)?;
    ensure!(
        t.get_u8(1)? == Some(SUITE_80),
        "suite SRTP distinta de AES_CM_128_HMAC_SHA1_80"
    );
    Ok(SrtpParams {
        key: t
            .get(2)
            .and_then(|k| k.try_into().ok())
            .context("SRTP key has invalid length")?,
        salt: t
            .get(3)
            .and_then(|k| k.try_into().ok())
            .context("SRTP salt has invalid length")?,
    })
}

pub fn parse_request(tlv: &[u8]) -> Result<EndpointRequest> {
    let t = Tlv8::parse(tlv)?;
    let session_id = t
        .get(1)
        .and_then(|s| s.try_into().ok())
        .context("session id missing or invalid length")?;
    let a = Tlv8::parse(t.get(3).context("missing address")?)?;
    let addr: IpAddr = std::str::from_utf8(a.get(2).context("missing IP")?)?
        .parse()
        .context("invalid controller IP")?;
    ensure!(
        a.get_u8(1)?.map(|v| v == 1) == Some(addr.is_ipv6()),
        "IP version does not match address"
    );
    let port = |tag| -> Result<u16> {
        match a.get_u16(tag)? {
            Some(p) if p != 0 => Ok(p),
            _ => bail!("{tag} port missing or 0"),
        }
    };
    Ok(EndpointRequest {
        session_id,
        addr,
        video_port: port(3)?,
        audio_port: port(4)?,
        video_srtp: parse_srtp(
            t.get(4)
                .ok_or_else(|| anyhow!("missing video SRTP params"))?,
        )?,
        audio_srtp: parse_srtp(
            t.get(5)
                .ok_or_else(|| anyhow!("missing audio SRTP params"))?,
        )?,
    })
}

fn srtp_tlv(p: &SrtpParams) -> Vec<u8> {
    Tlv8::new()
        .push_u8(1, SUITE_80)
        .push(2, &p.key)
        .push(3, &p.salt)
        .encode()
}

/// Success response. The ports in `req` are the ones the accessory advertises (where it listens
/// for the return RTCP); keys are mirrored the same way HAP-NodeJS does.
pub fn build_response(
    req: &EndpointRequest,
    local_ip: IpAddr,
    video_ssrc: u32,
    audio_ssrc: u32,
) -> Vec<u8> {
    let addr = Tlv8::new()
        .push_u8(1, local_ip.is_ipv6() as u8)
        .push(2, local_ip.to_string().as_bytes())
        .push(3, &req.video_port.to_le_bytes())
        .push(4, &req.audio_port.to_le_bytes())
        .encode();
    Tlv8::new()
        .push(1, &req.session_id)
        .push_u8(2, 0)
        .push(3, &addr)
        .push(4, &srtp_tlv(&req.video_srtp))
        .push(5, &srtp_tlv(&req.audio_srtp))
        .push_u32(6, video_ssrc)
        .push_u32(7, audio_ssrc)
        .encode()
}

#[cfg(test)]
mod tests {
    use super::*;

    pub const FIXTURE: &[u8] = include_bytes!("../../tests/fixtures/setup_endpoints.tlv");

    #[test]
    fn parse_setup_endpoints_fixture() {
        let r = parse_request(FIXTURE).unwrap();
        assert_eq!(r.addr, "192.168.50.18".parse::<IpAddr>().unwrap());
        assert_eq!((r.video_port, r.audio_port), (0xde6d, 0xefc3));
        assert_eq!(r.session_id[..4], [0x17, 0xc4, 0x0f, 0xa8]);
        assert_eq!(r.video_srtp.key, [0; 16]);
    }

    #[test]
    fn response_roundtrips_fields() {
        let r = parse_request(FIXTURE).unwrap();
        let resp = build_response(&r, "192.168.50.5".parse().unwrap(), 0x11, 0x22);
        let t = Tlv8::parse(&resp).unwrap();
        assert_eq!(t.get(1).unwrap(), r.session_id);
        assert_eq!(t.get_u8(2).unwrap(), Some(0));
        assert_eq!(t.get_u32(6).unwrap(), Some(0x11));
        assert_eq!(t.get_u32(7).unwrap(), Some(0x22));
        let a = Tlv8::parse(t.get(3).unwrap()).unwrap();
        assert_eq!(a.get(2).unwrap(), b"192.168.50.5");
        assert_eq!(a.get_u16(3).unwrap(), Some(r.video_port));
        assert_eq!(parse_srtp(t.get(4).unwrap()).unwrap(), r.video_srtp);
    }

    #[test]
    fn rejects_truncated_and_other_suite() {
        assert!(parse_request(&FIXTURE[..40]).is_err());
        let mut b = FIXTURE.to_vec();
        let i = b.windows(3).position(|w| w == [1, 1, 0]).unwrap();
        // the first "01 01 00" is the IP version; the next one is the video suite
        let j = b[i + 3..].windows(3).position(|w| w == [1, 1, 0]).unwrap() + i + 3;
        b[j + 2] = 2; // DISABLED
        assert!(parse_request(&b).is_err());
    }
}
