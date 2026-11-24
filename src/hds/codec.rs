//! HDS DataStream format (Apple's "OPACK"). Reference: HAP-NodeJS `DataStreamParser.ts`.
//!
//! The decoder understands the whole format (including back-references and terminated
//! forms). The encoder always emits the shortest form without back-references,
//! which any decoder accepts.

use anyhow::{Result, bail, ensure};
use bytes::Bytes;

#[derive(Clone, Debug, PartialEq)]
pub enum DsValue {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    Data(Bytes),
    Array(Vec<DsValue>),
    Dict(Vec<(String, DsValue)>),
}

impl DsValue {
    pub fn dict<const N: usize>(items: [(&str, DsValue); N]) -> Self {
        Self::Dict(items.into_iter().map(|(k, v)| (k.to_owned(), v)).collect())
    }

    pub fn dict_vec(items: Vec<(&str, DsValue)>) -> Self {
        Self::Dict(items.into_iter().map(|(k, v)| (k.to_owned(), v)).collect())
    }

    pub fn get(&self, key: &str) -> Option<&DsValue> {
        match self {
            Self::Dict(d) => d.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn as_int(&self) -> Option<i64> {
        match self {
            Self::Int(i) => Some(*i),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode_into(&mut out);
        out
    }

    pub fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            Self::Null => out.push(0x04),
            Self::Bool(b) => out.push(if *b { 0x01 } else { 0x02 }),
            Self::Int(i) => encode_int(*i, out),
            Self::Float(f) => {
                out.push(0x36);
                out.extend_from_slice(&f.to_le_bytes());
            }
            Self::Str(s) => encode_len(0x40, 0x61, s.len(), out).extend_from_slice(s.as_bytes()),
            Self::Data(d) => encode_len(0x70, 0x91, d.len(), out).extend_from_slice(d),
            Self::Array(a) => {
                out.push(if a.len() <= 14 {
                    0xD0 + a.len() as u8
                } else {
                    0xDF
                });
                a.iter().for_each(|v| v.encode_into(out));
                if a.len() > 14 {
                    out.push(0x03);
                }
            }
            Self::Dict(d) => {
                out.push(if d.len() <= 14 {
                    0xE0 + d.len() as u8
                } else {
                    0xEF
                });
                for (k, v) in d {
                    Self::Str(k.clone()).encode_into(out);
                    v.encode_into(out);
                }
                if d.len() > 14 {
                    out.push(0x03);
                }
            }
        }
    }

    /// Decodes a value; `buf` must be fully consumed.
    pub fn decode(buf: &[u8]) -> Result<DsValue> {
        let mut r = Reader {
            buf,
            pos: 0,
            tracked: Vec::new(),
        };
        let v = r.value()?;
        ensure!(r.pos == buf.len(), "trailing bytes after the value");
        match v {
            Some(v) => Ok(v),
            None => bail!("unexpected terminator"),
        }
    }
}

/// Writes the length tag (short `short + len` up to 32, otherwise 8/16/32/64-bit LE).
fn encode_len(short: u8, long: u8, len: usize, out: &mut Vec<u8>) -> &mut Vec<u8> {
    if len <= 32 {
        out.push(short + len as u8);
    } else if len <= 0xFF {
        out.extend_from_slice(&[long, len as u8]);
    } else if len <= 0xFFFF {
        out.push(long + 1);
        out.extend_from_slice(&(len as u16).to_le_bytes());
    } else if len <= 0xFFFF_FFFF {
        out.push(long + 2);
        out.extend_from_slice(&(len as u32).to_le_bytes());
    } else {
        out.push(long + 3);
        out.extend_from_slice(&(len as u64).to_le_bytes());
    }
    out
}

fn encode_int(i: i64, out: &mut Vec<u8>) {
    if i == -1 {
        out.push(0x07);
    } else if (0..=38).contains(&i) {
        out.push(0x08 + i as u8);
    } else if let Ok(v) = i8::try_from(i) {
        out.extend_from_slice(&[0x30, v as u8]);
    } else if let Ok(v) = i16::try_from(i) {
        out.push(0x31);
        out.extend_from_slice(&v.to_le_bytes());
    } else if let Ok(v) = i32::try_from(i) {
        out.push(0x32);
        out.extend_from_slice(&v.to_le_bytes());
    } else {
        out.push(0x33);
        out.extend_from_slice(&i.to_le_bytes());
    }
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
    /// Values longer than one byte, in read order, for back-references.
    tracked: Vec<DsValue>,
}

impl Reader<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8]> {
        ensure!(self.buf.len() - self.pos >= n, "unexpected end of data");
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    fn le(&mut self, n: usize) -> Result<u64> {
        let b = self.take(n)?;
        Ok(b.iter().rev().fold(0u64, |a, &x| (a << 8) | u64::from(x)))
    }

    fn track(&mut self, v: DsValue) -> DsValue {
        self.tracked.push(v.clone());
        v
    }

    fn len_or_term(&mut self, n: usize) -> Result<usize> {
        let l = self.le(n)?;
        ensure!(l <= self.buf.len() as u64, "length out of range");
        Ok(l as usize)
    }

    fn string(&mut self, len: usize) -> Result<DsValue> {
        let s = String::from_utf8(self.take(len)?.to_vec())?;
        Ok(if len == 0 {
            DsValue::Str(s)
        } else {
            self.track(DsValue::Str(s))
        })
    }

    fn data(&mut self, len: usize) -> Result<DsValue> {
        let d = DsValue::Data(Bytes::copy_from_slice(self.take(len)?));
        Ok(if len == 0 { d } else { self.track(d) })
    }

    /// `None` = terminator (0x03), only valid inside terminated arrays/dictionaries.
    fn value(&mut self) -> Result<Option<DsValue>> {
        let tag = self.take(1)?[0];
        Ok(Some(match tag {
            0x03 => return Ok(None),
            0x01 => DsValue::Bool(true),
            0x02 => DsValue::Bool(false),
            0x04 => DsValue::Null,
            // ponytail: uuid as Data(16) and date as Float (seconds since 2001); dataSend does not use them.
            0x05 => {
                let d = self.take(16)?.to_vec();
                self.track(DsValue::Data(d.into()))
            }
            0x06 => {
                let f = f64::from_le_bytes(self.take(8)?.try_into()?);
                self.track(DsValue::Float(f))
            }
            0x07 => DsValue::Int(-1),
            0x08..=0x2F => DsValue::Int(i64::from(tag - 0x08)),
            0x30 => {
                let v = self.take(1)?[0] as i8;
                self.track(DsValue::Int(v.into()))
            }
            0x31 => {
                let v = self.le(2)? as u16 as i16;
                self.track(DsValue::Int(v.into()))
            }
            0x32 => {
                let v = self.le(4)? as u32 as i32;
                self.track(DsValue::Int(v.into()))
            }
            0x33 => {
                let v = self.le(8)? as i64;
                self.track(DsValue::Int(v))
            }
            0x35 => {
                let f = f32::from_le_bytes(self.take(4)?.try_into()?);
                self.track(DsValue::Float(f.into()))
            }
            0x36 => {
                let f = f64::from_le_bytes(self.take(8)?.try_into()?);
                self.track(DsValue::Float(f))
            }
            0x40..=0x60 => self.string(usize::from(tag - 0x40))?,
            0x61..=0x64 => {
                let l = self.len_or_term(1 << (tag - 0x61))?;
                self.string(l)?
            }
            0x6F => {
                let rest = &self.buf[self.pos..];
                let Some(end) = rest.iter().position(|&b| b == 0) else {
                    bail!("unterminated string");
                };
                let s = self.string(end)?;
                self.pos += 1;
                s
            }
            0x70..=0x90 => self.data(usize::from(tag - 0x70))?,
            0x91..=0x94 => {
                let l = self.len_or_term(1 << (tag - 0x91))?;
                self.data(l)?
            }
            // ponytail: terminated data (0x9F) unsupported; no known controller sends it.
            0x9F => bail!("terminated data not supported"),
            0xA0..=0xCF => {
                let i = usize::from(tag - 0xA0);
                match self.tracked.get(i) {
                    Some(v) => v.clone(),
                    None => bail!("back-reference out of range ({i})"),
                }
            }
            0xD0..=0xDE => {
                let mut a = Vec::new();
                for _ in 0..tag - 0xD0 {
                    a.push(self.item()?);
                }
                DsValue::Array(a)
            }
            0xDF => {
                let mut a = Vec::new();
                while let Some(v) = self.value()? {
                    a.push(v);
                }
                DsValue::Array(a)
            }
            0xE0..=0xEE => {
                let mut d = Vec::new();
                for _ in 0..tag - 0xE0 {
                    let k = self.key()?;
                    d.push((k, self.item()?));
                }
                DsValue::Dict(d)
            }
            0xEF => {
                let mut d = Vec::new();
                while let Some(k) = self.value()? {
                    let DsValue::Str(k) = k else {
                        bail!("dictionary key is not text");
                    };
                    d.push((k, self.item()?));
                }
                DsValue::Dict(d)
            }
            t => bail!("unknown tag 0x{t:02X}"),
        }))
    }

    fn item(&mut self) -> Result<DsValue> {
        self.value()?
            .ok_or_else(|| anyhow::anyhow!("unexpected terminator"))
    }

    fn key(&mut self) -> Result<String> {
        match self.item()? {
            DsValue::Str(s) => Ok(s),
            _ => bail!("dictionary key is not text"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rt(v: DsValue) {
        assert_eq!(DsValue::decode(&v.encode()).unwrap(), v);
    }

    #[test]
    fn codec_roundtrip_all_types() {
        for i in [
            0i64,
            1,
            38,
            39,
            127,
            128,
            -1,
            -2,
            -128,
            -129,
            32767,
            32768,
            70000,
            -70000,
            2_147_483_647,
            2_147_483_648,
            i64::MAX,
            i64::MIN,
        ] {
            rt(DsValue::Int(i));
        }
        rt(DsValue::Null);
        rt(DsValue::Bool(true));
        rt(DsValue::Bool(false));
        rt(DsValue::Float(1.5));
        rt(DsValue::Float(-0.25e10));
        for n in [0usize, 1, 32, 33, 255, 256, 70000] {
            rt(DsValue::Str("é".repeat(n)));
            rt(DsValue::Data(Bytes::from(vec![7u8; n])));
        }
        rt(DsValue::Array((0..20).map(DsValue::Int).collect()));
        rt(DsValue::Array(vec![]));
        rt(DsValue::Dict(
            (0..20)
                .map(|i| (format!("k{i}"), DsValue::Int(i)))
                .collect(),
        ));
        rt(DsValue::dict([
            (
                "a",
                DsValue::Array(vec![DsValue::Null, DsValue::Str("x".into())]),
            ),
            (
                "b",
                DsValue::dict([("c", DsValue::Data(Bytes::from_static(b"zz")))]),
            ),
        ]));
    }

    #[test]
    fn codec_known_encodings() {
        assert_eq!(DsValue::Int(5).encode(), [0x0D]);
        assert_eq!(DsValue::Int(-1).encode(), [0x07]);
        assert_eq!(DsValue::Int(100).encode(), [0x30, 100]);
        assert_eq!(DsValue::Str("ab".into()).encode(), [0x42, b'a', b'b']);
        assert_eq!(
            DsValue::dict([("a", DsValue::Bool(true))]).encode(),
            [0xE1, 0x41, b'a', 0x01]
        );
    }

    /// Vectors from HAP-NodeJS's `DataStreamParser.spec.ts` (go2rtc does not ship codec vectors).
    #[test]
    fn codec_decodes_reference_vectors() {
        // { a: true, b: <ref 1> }: "a" is index 0, `true` is not registered, "b" is 1.
        let v = DsValue::decode(&[0xE2, 0x41, 0x61, 0x01, 0x41, 0x62, 0xA1]).unwrap();
        assert_eq!(
            v,
            DsValue::dict([("a", DsValue::Bool(true)), ("b", DsValue::Str("b".into()))])
        );
        // { a: '', b: 'x', c: <ref 2> }: the empty string is not registered.
        let v = DsValue::decode(&[
            0xE3, 0x41, 0x61, 0x40, 0x41, 0x62, 0x41, 0x78, 0x41, 0x63, 0xA2,
        ])
        .unwrap();
        assert_eq!(
            v,
            DsValue::dict([
                ("a", DsValue::Str(String::new())),
                ("b", DsValue::Str("x".into())),
                ("c", DsValue::Str("x".into())),
            ])
        );
        // Terminated forms: dict {a: [1]} with 0xEF/0xDF.
        let v = DsValue::decode(&[0xEF, 0x41, b'a', 0xDF, 0x09, 0x03, 0x03]).unwrap();
        assert_eq!(
            v,
            DsValue::dict([("a", DsValue::Array(vec![DsValue::Int(1)]))])
        );
    }

    #[test]
    fn codec_rejects_garbage() {
        assert!(DsValue::decode(&[]).is_err());
        assert!(DsValue::decode(&[0x00]).is_err());
        assert!(DsValue::decode(&[0x45, b'a']).is_err());
        assert!(DsValue::decode(&[0x01, 0x01]).is_err());
        assert!(DsValue::decode(&[0xA0]).is_err());
        assert!(DsValue::decode(&[0x94, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F]).is_err());
    }
}
