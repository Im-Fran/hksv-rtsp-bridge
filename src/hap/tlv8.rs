//! HAP TLV8 encoding (type-length-value with values up to 255 bytes).

use anyhow::{Result, bail};

/// HAP separator: splits repeated values of the same type.
pub const SEPARATOR: u8 = 0xFF;

/// HAP TLV types.
pub const T_METHOD: u8 = 0;
pub const T_IDENTIFIER: u8 = 1;
pub const T_SALT: u8 = 2;
pub const T_PUBLIC_KEY: u8 = 3;
pub const T_PROOF: u8 = 4;
pub const T_ENCRYPTED: u8 = 5;
pub const T_STATE: u8 = 6;
pub const T_ERROR: u8 = 7;
pub const T_SIGNATURE: u8 = 10;
pub const T_PERMISSIONS: u8 = 11;

/// HAP error codes (kTLVError_*).
pub const ERR_UNKNOWN: u8 = 1;
pub const ERR_AUTHENTICATION: u8 = 2;
pub const ERR_BACKOFF: u8 = 3;
pub const ERR_MAX_PEERS: u8 = 4;
pub const ERR_MAX_TRIES: u8 = 5;
pub const ERR_UNAVAILABLE: u8 = 6;
pub const ERR_BUSY: u8 = 7;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Tlv8(Vec<(u8, Vec<u8>)>);

impl Tlv8 {
    pub fn new() -> Self {
        Self::default()
    }

    /// Decodes TLV8; consecutive fragments of the same type are reassembled.
    pub fn parse(b: &[u8]) -> Result<Tlv8> {
        let mut items: Vec<(u8, Vec<u8>)> = Vec::new();
        let mut pos = 0;
        while pos < b.len() {
            if pos + 2 > b.len() {
                bail!("TLV8 truncated at offset {pos}");
            }
            let (t, len) = (b[pos], b[pos + 1] as usize);
            let end = pos + 2 + len;
            if end > b.len() {
                bail!("TLV8 truncated: type {t} declares {len} bytes at offset {pos}");
            }
            let v = &b[pos + 2..end];
            match items.last_mut() {
                Some((lt, lv)) if *lt == t => lv.extend_from_slice(v),
                _ => items.push((t, v.to_vec())),
            }
            pos = end;
        }
        Ok(Tlv8(items))
    }

    /// First value of type `t`.
    pub fn get(&self, t: u8) -> Option<&[u8]> {
        self.0
            .iter()
            .find(|(x, _)| *x == t)
            .map(|(_, v)| v.as_slice())
    }

    /// All values of type `t`, separated by `push_sep`.
    pub fn get_all(&self, t: u8) -> Vec<&[u8]> {
        self.0
            .iter()
            .filter(|(x, _)| *x == t)
            .map(|(_, v)| v.as_slice())
            .collect()
    }

    /// Encodes; values >255 bytes are split into 255-byte chunks.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for (t, v) in &self.0 {
            if v.is_empty() {
                out.extend_from_slice(&[*t, 0]);
            }
            for chunk in v.chunks(255) {
                out.extend_from_slice(&[*t, chunk.len() as u8]);
                out.extend_from_slice(chunk);
            }
        }
        out
    }

    pub fn push(mut self, t: u8, v: &[u8]) -> Self {
        self.0.push((t, v.to_vec()));
        self
    }

    pub fn push_u8(self, t: u8, v: u8) -> Self {
        self.push(t, &v.to_le_bytes())
    }

    pub fn push_u32(self, t: u8, v: u32) -> Self {
        self.push(t, &v.to_le_bytes())
    }

    pub fn push_u64(self, t: u8, v: u64) -> Self {
        self.push(t, &v.to_le_bytes())
    }

    pub fn push_sep(self) -> Self {
        self.push(SEPARATOR, &[])
    }

    /// Little-endian integer of up to 1 byte; absent = `None`.
    pub fn get_u8(&self, t: u8) -> Result<Option<u8>> {
        Ok(self.get_le(t, 1)?.map(|v| v as u8))
    }

    /// Little-endian integer of up to 2 bytes; absent = `None`.
    pub fn get_u16(&self, t: u8) -> Result<Option<u16>> {
        Ok(self.get_le(t, 2)?.map(|v| v as u16))
    }

    /// Little-endian integer of up to 4 bytes; absent = `None`.
    pub fn get_u32(&self, t: u8) -> Result<Option<u32>> {
        Ok(self.get_le(t, 4)?.map(|v| v as u32))
    }

    /// Little-endian integer of up to 8 bytes; absent = `None`.
    pub fn get_u64(&self, t: u8) -> Result<Option<u64>> {
        self.get_le(t, 8)
    }

    /// Little-endian of at most `width` bytes; short values are zero-padded.
    fn get_le(&self, t: u8, width: usize) -> Result<Option<u64>> {
        let Some(v) = self.get(t) else {
            return Ok(None);
        };
        if v.len() > width {
            bail!("TLV8 type {t}: {} bytes, max {width}", v.len());
        }
        let mut buf = [0u8; 8];
        buf[..v.len()].copy_from_slice(v);
        Ok(Some(u64::from_le_bytes(buf)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fragments_over_255() {
        let big: Vec<u8> = (0..300).map(|i| i as u8).collect();
        let enc = Tlv8::new().push(7, &big).encode();
        assert_eq!(enc[0], 7);
        assert_eq!(enc[1], 255);
        assert_eq!(enc[257], 7);
        assert_eq!(enc[258], 45);
        assert_eq!(enc.len(), 2 + 255 + 2 + 45);
        let parsed = Tlv8::parse(&enc).unwrap();
        assert_eq!(parsed.get(7), Some(&big[..]));
        assert_eq!(parsed.get_all(7).len(), 1);
    }

    #[test]
    fn repeated_types_with_separator() {
        let b = [1, 1, 0xaa, SEPARATOR, 0, 1, 1, 0xbb];
        let t = Tlv8::parse(&b).unwrap();
        assert_eq!(t.get_all(1), vec![&[0xaa][..], &[0xbb][..]]);
        assert_eq!(t.get(1), Some(&[0xaa][..]));
    }

    #[test]
    fn truncated_is_error() {
        assert!(Tlv8::parse(&[1, 5, 0, 0]).is_err());
        assert!(Tlv8::parse(&[1]).is_err());
    }

    #[test]
    fn empty_value() {
        let t = Tlv8::parse(&[6, 0]).unwrap();
        assert_eq!(t.get(6), Some(&[][..]));
        assert_eq!(t.encode(), vec![6, 0]);
    }

    #[test]
    fn push_integers_little_endian() {
        let t = Tlv8::new()
            .push_u8(1, 0x7f)
            .push_u32(2, 0x0102_0304)
            .push_u64(3, 1)
            .push_sep();
        assert_eq!(t.get(1), Some(&[0x7f][..]));
        assert_eq!(t.get(2), Some(&[4, 3, 2, 1][..]));
        assert_eq!(t.get(3), Some(&[1, 0, 0, 0, 0, 0, 0, 0][..]));
        assert_eq!(t.encode().last_chunk::<2>(), Some(&[0xFF, 0]));
    }

    #[test]
    fn get_integers_accept_short_values() {
        let t = Tlv8::parse(&[1, 1, 9, 2, 2, 0x34, 0x12, 3, 0]).unwrap();
        assert_eq!(t.get_u8(1).unwrap(), Some(9));
        assert_eq!(t.get_u16(2).unwrap(), Some(0x1234));
        assert_eq!(t.get_u32(3).unwrap(), Some(0));
        assert_eq!(t.get_u64(4).unwrap(), None);
    }

    #[test]
    fn get_integers_reject_too_long() {
        let t = Tlv8::new().push(1, &[1, 2]);
        assert!(t.get_u8(1).is_err());
        let t = Tlv8::new().push(1, &[0; 9]);
        assert!(t.get_u64(1).is_err());
    }
}
