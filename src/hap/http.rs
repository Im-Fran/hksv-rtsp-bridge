//! Minimal HTTP/1.1 for HAP: only `Content-Length`, no chunked encoding or negotiated keep-alive.

use anyhow::{Result, bail};
use bytes::{Buf, BytesMut};

const MAX_HEAD: usize = 16 * 1024;
const MAX_BODY: usize = 1024 * 1024;

pub const CT_TLV8: &str = "application/pairing+tlv8";
pub const CT_JSON: &str = "application/hap+json";

#[derive(Debug)]
pub struct Request {
    pub method: String,
    /// Path with query string (`/characteristics?id=1.10`).
    pub target: String,
    pub body: Vec<u8>,
}

impl Request {
    pub fn path(&self) -> &str {
        self.target.split('?').next().unwrap_or("")
    }

    pub fn query(&self) -> &str {
        self.target.split_once('?').map_or("", |(_, q)| q)
    }
}

/// Extracts the first complete request from `buf` (consuming it). `Ok(None)` if bytes are missing.
pub fn parse(buf: &mut BytesMut) -> Result<Option<Request>> {
    let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
        if buf.len() > MAX_HEAD {
            bail!("HTTP header too long");
        }
        return Ok(None);
    };
    let head = std::str::from_utf8(&buf[..end])?;
    let mut lines = head.split("\r\n");
    let mut first = lines.next().unwrap_or("").split(' ');
    let (Some(method), Some(target), Some(_)) = (first.next(), first.next(), first.next()) else {
        bail!("invalid request line");
    };
    let mut len = 0usize;
    for l in lines {
        if let Some((k, v)) = l.split_once(':') {
            if k.eq_ignore_ascii_case("content-length") {
                len = v.trim().parse()?;
            } else if k.eq_ignore_ascii_case("transfer-encoding") {
                bail!("Transfer-Encoding not supported");
            }
        }
    }
    if len > MAX_BODY {
        bail!("body too large");
    }
    if buf.len() < end + 4 + len {
        return Ok(None);
    }
    let req = Request {
        method: method.into(),
        target: target.into(),
        body: buf[end + 4..end + 4 + len].to_vec(),
    };
    buf.advance(end + 4 + len);
    Ok(Some(req))
}

pub struct Response {
    pub status: u16,
    pub content_type: &'static str,
    pub body: Vec<u8>,
}

impl Response {
    pub fn new(status: u16, content_type: &'static str, body: Vec<u8>) -> Self {
        Self {
            status,
            content_type,
            body,
        }
    }

    pub fn json(status: u16, v: &serde_json::Value) -> Self {
        Self::new(status, CT_JSON, v.to_string().into_bytes())
    }

    pub fn tlv(body: Vec<u8>) -> Self {
        Self::new(200, CT_TLV8, body)
    }

    pub fn empty(status: u16) -> Self {
        Self::new(status, CT_JSON, Vec::new())
    }

    pub fn format(&self) -> Vec<u8> {
        let reason = match self.status {
            200 => "OK",
            204 => "No Content",
            207 => "Multi-Status",
            400 => "Bad Request",
            404 => "Not Found",
            470 => "Connection Authorization Required",
            _ => "Internal Server Error",
        };
        let mut out = format!("HTTP/1.1 {} {reason}\r\n", self.status).into_bytes();
        if !self.body.is_empty() {
            out.extend(
                format!(
                    "Content-Type: {}\r\nContent-Length: {}\r\n",
                    self.content_type,
                    self.body.len()
                )
                .bytes(),
            );
        } else {
            out.extend(b"Content-Length: 0\r\n");
        }
        out.extend(b"\r\n");
        out.extend(&self.body);
        out
    }
}

pub fn format_event(body: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "EVENT/1.0 200 OK\r\nContent-Type: {CT_JSON}\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    out.extend(body);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_split_and_pipelined() {
        let raw = b"PUT /characteristics HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\n\r\nabcdGET /accessories HTTP/1.1\r\n\r\n";
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&raw[..40]);
        assert!(parse(&mut buf).unwrap().is_none());
        buf.extend_from_slice(&raw[40..]);
        let a = parse(&mut buf).unwrap().unwrap();
        assert_eq!(
            (a.method.as_str(), a.path(), a.body.as_slice()),
            ("PUT", "/characteristics", &b"abcd"[..])
        );
        let b = parse(&mut buf).unwrap().unwrap();
        assert_eq!(b.path(), "/accessories");
        assert!(parse(&mut buf).unwrap().is_none());
    }

    #[test]
    fn query_and_chunked() {
        let mut buf = BytesMut::from(&b"GET /characteristics?id=1.10,1.11 HTTP/1.1\r\n\r\n"[..]);
        assert_eq!(parse(&mut buf).unwrap().unwrap().query(), "id=1.10,1.11");
        let mut buf =
            BytesMut::from(&b"POST /x HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"[..]);
        assert!(parse(&mut buf).is_err());
    }

    #[test]
    fn formats_response() {
        let r = Response::json(207, &serde_json::json!({"a": 1})).format();
        assert_eq!(
            String::from_utf8(r).unwrap(),
            "HTTP/1.1 207 Multi-Status\r\nContent-Type: application/hap+json\r\nContent-Length: 7\r\n\r\n{\"a\":1}"
        );
        assert!(
            Response::empty(204)
                .format()
                .starts_with(b"HTTP/1.1 204 No Content\r\n")
        );
    }
}
