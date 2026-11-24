//! HDS connection: encrypted frames, `control/hello`, and the `dataSend` protocol primitives.

use anyhow::{Result, anyhow, bail, ensure};
use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::codec::DsValue;
use crate::hap::crypto::{counter_nonce, hkdf_sha512, open_raw, seal_raw};

const TAG: usize = 16;
/// Maximum payload per frame (HAP-NodeJS `MAX_PAYLOAD_LENGTH`).
const MAX_PAYLOAD: usize = 0xF_FFFF;
/// Data chunk size in `dataSend` (HAP-NodeJS uses 256 KiB).
pub const DATA_CHUNK: usize = 0x40000;

/// HDS statuses (`status` of responses).
pub const STATUS_OK: i64 = 0;
pub const STATUS_PROTOCOL_SPECIFIC_ERROR: i64 = 6;

/// `dataSend` reasons (`status` in the `open` body and `reason` of `close`).
pub mod reason {
    pub const NORMAL: i64 = 0;
    pub const NOT_ALLOWED: i64 = 1;
    pub const BUSY: i64 = 2;
    pub const CANCELLED: i64 = 3;
    pub const UNSUPPORTED: i64 = 4;
    pub const UNEXPECTED_FAILURE: i64 = 5;
    pub const TIMEOUT: i64 = 6;
    pub const BAD_DATA: i64 = 7;
    pub const PROTOCOL_ERROR: i64 = 8;
    pub const INVALID_CONFIGURATION: i64 = 9;
}

/// Accessory-side keys.
#[derive(Clone)]
pub struct HdsKeys {
    /// accessory -> controller ("HDS-Read-Encryption-Key").
    pub encrypt: [u8; 32],
    /// controller -> accessory ("HDS-Write-Encryption-Key").
    pub decrypt: [u8; 32],
}

impl HdsKeys {
    pub fn derive(shared_secret: &[u8; 32], controller_salt: &[u8], accessory_salt: &[u8]) -> Self {
        let salt = [controller_salt, accessory_salt].concat();
        Self {
            encrypt: hkdf_sha512(shared_secret, &salt, b"HDS-Read-Encryption-Key"),
            decrypt: hkdf_sha512(shared_secret, &salt, b"HDS-Write-Encryption-Key"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Event,
    Request,
    Response,
}

#[derive(Clone, Debug)]
pub struct Message {
    pub kind: Kind,
    pub protocol: String,
    pub topic: String,
    /// Only in request/response.
    pub id: Option<i64>,
    /// Only in response.
    pub status: Option<i64>,
    pub body: DsValue,
}

/// Controller's `dataSend/open` (HKSV: `type = "ipcamera.recording"`, `target = "controller"`).
#[derive(Clone, Debug, PartialEq)]
pub struct DataSendRequest {
    /// Request id (for replying).
    pub id: i64,
    pub stream_id: i64,
    pub type_: String,
    pub target: String,
    pub reason: Option<String>,
}

impl Message {
    pub fn is(&self, kind: Kind, protocol: &str, topic: &str) -> bool {
        self.kind == kind && self.protocol == protocol && self.topic == topic
    }

    /// `Some` if it is a well-formed `dataSend/open` request.
    pub fn as_data_send_open(&self) -> Option<DataSendRequest> {
        if !self.is(Kind::Request, "dataSend", "open") {
            return None;
        }
        Some(DataSendRequest {
            id: self.id?,
            stream_id: self.body.get("streamId")?.as_int()?,
            type_: self.body.get("type")?.as_str()?.to_owned(),
            target: self.body.get("target")?.as_str()?.to_owned(),
            reason: self
                .body
                .get("reason")
                .and_then(DsValue::as_str)
                .map(str::to_owned),
        })
    }

    /// `streamId` from the body (`dataSend/close` and `dataSend/ack` events).
    pub fn stream_id(&self) -> Option<i64> {
        self.body.get("streamId")?.as_int()
    }
}

fn parse_payload(p: &[u8]) -> Result<Message> {
    let hlen = usize::from(*p.first().ok_or_else(|| anyhow!("empty payload"))?);
    ensure!(hlen < p.len(), "HDS header longer than payload");
    let header = DsValue::decode(&p[1..=hlen])?;
    let body = DsValue::decode(&p[1 + hlen..])?;
    let s = |k: &str| header.get(k).and_then(DsValue::as_str).map(str::to_owned);
    let (kind, topic) = if let Some(t) = s("event") {
        (Kind::Event, t)
    } else if let Some(t) = s("request") {
        (Kind::Request, t)
    } else if let Some(t) = s("response") {
        (Kind::Response, t)
    } else {
        bail!("HDS header without event/request/response");
    };
    Ok(Message {
        kind,
        protocol: s("protocol").unwrap_or_default(),
        topic,
        id: header.get("id").and_then(DsValue::as_int),
        status: header.get("status").and_then(DsValue::as_int),
        body,
    })
}

pub struct HdsConn<S> {
    io: S,
    keys: HdsKeys,
    enc_ctr: u64,
    dec_ctr: u64,
    buf: BytesMut,
}

impl<S: AsyncRead + AsyncWrite + Unpin> HdsConn<S> {
    pub fn new(io: S, keys: HdsKeys) -> Self {
        Self {
            io,
            keys,
            enc_ctr: 0,
            dec_ctr: 0,
            buf: BytesMut::new(),
        }
    }

    /// Reads the first frame, identifies it with the key from `candidates` that decrypts it, requires
    /// `control/hello` and replies to it. Returns the index of the matching candidate.
    pub async fn accept(io: S, candidates: &[HdsKeys]) -> Result<(usize, Self)> {
        let mut conn = Self::new(
            io,
            candidates
                .first()
                .ok_or_else(|| anyhow!("no keys"))?
                .clone(),
        );
        let frame = conn.read_frame().await?;
        let (idx, payload) = candidates
            .iter()
            .enumerate()
            .find_map(|(i, k)| {
                open_raw(&k.decrypt, counter_nonce(0), &frame[..4], &frame[4..])
                    .ok()
                    .map(|p| (i, p))
            })
            .ok_or_else(|| anyhow!("no pending HDS session decrypts the first frame"))?;
        conn.keys = candidates[idx].clone();
        conn.dec_ctr = 1;
        let hello = parse_payload(&payload)?;
        ensure!(
            hello.is(Kind::Request, "control", "hello"),
            "first HDS message is not control/hello"
        );
        conn.send_response(
            "control",
            "hello",
            hello.id.unwrap_or(0),
            STATUS_OK,
            DsValue::Dict(vec![]),
        )
        .await?;
        Ok((idx, conn))
    }

    /// A complete frame (header + ciphertext + tag) without decrypting it. Cancel-safe: consumes
    /// nothing until the whole frame has arrived.
    async fn read_frame(&mut self) -> Result<Vec<u8>> {
        loop {
            if self.buf.len() >= 4 {
                ensure!(self.buf[0] == 1, "unknown HDS frame type {}", self.buf[0]);
                let len = (usize::from(self.buf[1]) << 16)
                    | (usize::from(self.buf[2]) << 8)
                    | usize::from(self.buf[3]);
                ensure!(len <= MAX_PAYLOAD, "frame HDS demasiado grande");
                if self.buf.len() >= 4 + len + TAG {
                    return Ok(self.buf.split_to(4 + len + TAG).to_vec());
                }
            }
            if self.io.read_buf(&mut self.buf).await? == 0 {
                bail!("HDS connection closed");
            }
        }
    }

    /// Next message from the controller. A repeated `control/hello` is answered automatically.
    /// Cancel-safe (can be used inside `select!`).
    pub async fn next_message(&mut self) -> Result<Message> {
        loop {
            let frame = self.read_frame().await?;
            let plain = open_raw(
                &self.keys.decrypt,
                counter_nonce(self.dec_ctr),
                &frame[..4],
                &frame[4..],
            )?;
            self.dec_ctr += 1;
            let msg = parse_payload(&plain)?;
            if msg.is(Kind::Request, "control", "hello") {
                self.send_response(
                    "control",
                    "hello",
                    msg.id.unwrap_or(0),
                    STATUS_OK,
                    DsValue::Dict(vec![]),
                )
                .await?;
                continue;
            }
            return Ok(msg);
        }
    }

    async fn send(&mut self, header: DsValue, body: DsValue) -> Result<()> {
        let h = header.encode();
        let mut payload = vec![u8::try_from(h.len())?];
        payload.extend_from_slice(&h);
        body.encode_into(&mut payload);
        ensure!(payload.len() <= MAX_PAYLOAD, "payload HDS demasiado grande");
        let n = payload.len();
        let fh = [1, (n >> 16) as u8, (n >> 8) as u8, n as u8];
        let mut out = fh.to_vec();
        out.extend(seal_raw(
            &self.keys.encrypt,
            counter_nonce(self.enc_ctr),
            &fh,
            &payload,
        ));
        self.enc_ctr += 1;
        self.io.write_all(&out).await?;
        self.io.flush().await?;
        Ok(())
    }

    /// Tests only: sends an arbitrary header/body (acts as the controller).
    #[cfg(test)]
    pub(crate) async fn send_raw_for_test(&mut self, header: DsValue, body: DsValue) {
        self.send(header, body).await.unwrap();
    }

    fn header(protocol: &str, kind: &str, topic: &str) -> Vec<(String, DsValue)> {
        vec![
            ("protocol".into(), DsValue::Str(protocol.into())),
            (kind.into(), DsValue::Str(topic.into())),
        ]
    }

    pub async fn send_event(&mut self, protocol: &str, topic: &str, body: DsValue) -> Result<()> {
        let h = Self::header(protocol, "event", topic);
        self.send(DsValue::Dict(h), body).await
    }

    pub async fn send_response(
        &mut self,
        protocol: &str,
        topic: &str,
        id: i64,
        status: i64,
        body: DsValue,
    ) -> Result<()> {
        let mut h = Self::header(protocol, "response", topic);
        h.push(("id".into(), DsValue::Int(id)));
        h.push(("status".into(), DsValue::Int(status)));
        self.send(DsValue::Dict(h), body).await
    }

    /// Accepts a `dataSend/open`: replies with success. Data is then sent with `send_data`.
    pub async fn accept_open(&mut self, req: &DataSendRequest) -> Result<()> {
        let body = DsValue::dict([("status", DsValue::Int(STATUS_OK))]);
        self.send_response("dataSend", "open", req.id, STATUS_OK, body)
            .await
    }

    /// Rejects a `dataSend/open` with a reason from [`reason`].
    pub async fn reject_open(&mut self, req: &DataSendRequest, why: i64) -> Result<()> {
        let body = DsValue::dict([("status", DsValue::Int(why))]);
        self.send_response(
            "dataSend",
            "open",
            req.id,
            STATUS_PROTOCOL_SPECIFIC_ERROR,
            body,
        )
        .await
    }

    /// Sends `data` as `dataSend/data` event(s), split into [`DATA_CHUNK`] pieces.
    /// `data_type`: `"mediaInitialization"` or `"mediaFragment"`; `seq` = dataSequenceNumber
    /// (starting at 1). `end_of_stream` is only set on the last chunk.
    pub async fn send_data(
        &mut self,
        stream_id: i64,
        data_type: &str,
        seq: i64,
        data: &[u8],
        end_of_stream: bool,
    ) -> Result<()> {
        let chunks: Vec<&[u8]> = if data.is_empty() {
            vec![data]
        } else {
            data.chunks(DATA_CHUNK).collect()
        };
        let last = chunks.len() - 1;
        for (i, c) in chunks.into_iter().enumerate() {
            let mut meta = vec![
                ("dataType", DsValue::Str(data_type.into())),
                ("dataSequenceNumber", DsValue::Int(seq)),
                ("dataChunkSequenceNumber", DsValue::Int(i as i64 + 1)),
                ("isLastDataChunk", DsValue::Bool(i == last)),
            ];
            if i == 0 {
                meta.push(("dataTotalSize", DsValue::Int(data.len() as i64)));
            }
            tracing::info!(
                "HDS -> dataSend/data stream={stream_id} type={data_type} dataSequenceNumber={seq} \
                 dataChunkSequenceNumber={} isLastDataChunk={} dataTotalSize={} bytes={} endOfStream={}",
                i + 1,
                i == last,
                if i == 0 {
                    data.len().to_string()
                } else {
                    "-".into()
                },
                c.len(),
                i == last && end_of_stream
            );
            let packet = DsValue::dict([
                ("data", DsValue::Data(Bytes::copy_from_slice(c))),
                ("metadata", DsValue::dict_vec(meta)),
            ]);
            let mut body = vec![
                ("streamId", DsValue::Int(stream_id)),
                ("packets", DsValue::Array(vec![packet])),
            ];
            if i == last {
                body.push(("endOfStream", DsValue::Bool(end_of_stream)));
            }
            self.send_event("dataSend", "data", DsValue::dict_vec(body))
                .await?;
        }
        Ok(())
    }

    /// `dataSend/close` initiated by the accessory.
    pub async fn send_close(&mut self, stream_id: i64, why: i64) -> Result<()> {
        let body = DsValue::dict([
            ("streamId", DsValue::Int(stream_id)),
            ("reason", DsValue::Int(why)),
        ]);
        self.send_event("dataSend", "close", body).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    fn keys() -> (HdsKeys, HdsKeys) {
        let acc = HdsKeys::derive(&[7; 32], &[1; 32], &[2; 32]);
        // The controller encrypts with "Write" and decrypts with "Read".
        let ctl = HdsKeys {
            encrypt: acc.decrypt,
            decrypt: acc.encrypt,
        };
        (acc, ctl)
    }

    #[test]
    fn frame_encrypt_decrypt() {
        let (acc, _) = keys();
        let hdr = [1, 0, 0, 4];
        let ct = seal_raw(&acc.encrypt, counter_nonce(0), &hdr, b"test");
        assert_eq!(ct.len(), 4 + TAG);
        assert_eq!(
            open_raw(&acc.encrypt, counter_nonce(0), &hdr, &ct).unwrap(),
            b"test"
        );
        // a different counter, header, or key makes it fail
        assert!(open_raw(&acc.encrypt, counter_nonce(1), &hdr, &ct).is_err());
        assert!(open_raw(&acc.encrypt, counter_nonce(0), &[1, 0, 0, 5], &ct).is_err());
        assert!(open_raw(&acc.decrypt, counter_nonce(0), &hdr, &ct).is_err());
        assert_ne!(acc.encrypt, acc.decrypt);
    }

    /// Simulated controller: sends a message in the HAP-NodeJS format.
    async fn ctl_send(
        c: &mut HdsConn<tokio::io::DuplexStream>,
        kind: &str,
        protocol: &str,
        topic: &str,
        id: i64,
        body: DsValue,
    ) {
        let mut h = HdsConn::<tokio::io::DuplexStream>::header(protocol, kind, topic);
        h.push(("id".into(), DsValue::Int(id)));
        c.send(DsValue::Dict(h), body).await.unwrap();
    }

    #[tokio::test]
    async fn hello_handshake() {
        let (a, b) = duplex(1 << 22);
        let (acc, ctl) = keys();
        let other = HdsKeys::derive(&[9; 32], &[1; 32], &[2; 32]);
        let mut c = HdsConn::new(b, ctl);
        ctl_send(
            &mut c,
            "request",
            "control",
            "hello",
            1234567,
            DsValue::Dict(vec![]),
        )
        .await;
        let (idx, mut srv) = HdsConn::accept(a, &[other, acc]).await.unwrap();
        assert_eq!(idx, 1);

        // hello response
        let frame = c.read_frame().await.unwrap();
        let p = open_raw(&c.keys.decrypt, counter_nonce(0), &frame[..4], &frame[4..]).unwrap();
        c.dec_ctr = 1;
        let m = parse_payload(&p).unwrap();
        assert!(m.is(Kind::Response, "control", "hello"));
        assert_eq!((m.id, m.status), (Some(1234567), Some(0)));

        // dataSend open -> respuesta -> datos -> ack/close
        let open = DsValue::dict([
            ("streamId", DsValue::Int(1)),
            ("type", DsValue::Str("ipcamera.recording".into())),
            ("target", DsValue::Str("controller".into())),
            ("reason", DsValue::Str("event".into())),
        ]);
        ctl_send(&mut c, "request", "dataSend", "open", 77, open).await;
        let msg = srv.next_message().await.unwrap();
        let req = msg.as_data_send_open().unwrap();
        assert_eq!(
            req,
            DataSendRequest {
                id: 77,
                stream_id: 1,
                type_: "ipcamera.recording".into(),
                target: "controller".into(),
                reason: Some("event".into())
            }
        );
        srv.accept_open(&req).await.unwrap();
        let m = c.next_message().await.unwrap();
        assert!(m.is(Kind::Response, "dataSend", "open"));
        assert_eq!((m.id, m.status), (Some(77), Some(0)));
        assert_eq!(m.body.get("status").and_then(DsValue::as_int), Some(0));

        let big = vec![5u8; DATA_CHUNK + 10];
        srv.send_data(1, "mediaFragment", 2, &big, true)
            .await
            .unwrap();
        let (m1, m2) = (
            c.next_message().await.unwrap(),
            c.next_message().await.unwrap(),
        );
        let pk = |m: &Message| match m.body.get("packets") {
            Some(DsValue::Array(a)) => a[0].clone(),
            _ => panic!("no packets"),
        };
        assert!(m1.is(Kind::Event, "dataSend", "data"));
        let (p1, p2) = (pk(&m1), pk(&m2));
        let meta = |p: &DsValue, k: &str| p.get("metadata").unwrap().get(k).cloned();
        assert_eq!(
            meta(&p1, "dataTotalSize"),
            Some(DsValue::Int(big.len() as i64))
        );
        assert_eq!(meta(&p1, "isLastDataChunk"), Some(DsValue::Bool(false)));
        assert_eq!(meta(&p2, "isLastDataChunk"), Some(DsValue::Bool(true)));
        assert_eq!(meta(&p2, "dataChunkSequenceNumber"), Some(DsValue::Int(2)));
        assert_eq!(
            meta(&p1, "dataType"),
            Some(DsValue::Str("mediaFragment".into()))
        );
        assert_eq!(m1.body.get("endOfStream"), None);
        assert_eq!(m2.body.get("endOfStream"), Some(&DsValue::Bool(true)));
        let Some(DsValue::Data(d2)) = p2.get("data") else {
            panic!()
        };
        assert_eq!(d2.len(), 10);

        ctl_send(
            &mut c,
            "event",
            "dataSend",
            "ack",
            0,
            DsValue::dict([
                ("streamId", DsValue::Int(1)),
                ("endOfStream", DsValue::Bool(true)),
            ]),
        )
        .await;
        let m = srv.next_message().await.unwrap();
        assert!(m.is(Kind::Event, "dataSend", "ack"));
        assert_eq!(m.stream_id(), Some(1));

        srv.send_close(1, reason::NORMAL).await.unwrap();
        let m = c.next_message().await.unwrap();
        assert!(m.is(Kind::Event, "dataSend", "close"));
        assert_eq!(m.body.get("reason").and_then(DsValue::as_int), Some(0));

        // a repeated hello is answered without leaving next_message
        ctl_send(
            &mut c,
            "request",
            "control",
            "hello",
            5,
            DsValue::Dict(vec![]),
        )
        .await;
        ctl_send(
            &mut c,
            "event",
            "dataSend",
            "close",
            0,
            DsValue::dict([("streamId", DsValue::Int(1))]),
        )
        .await;
        assert!(
            srv.next_message()
                .await
                .unwrap()
                .is(Kind::Event, "dataSend", "close")
        );
        assert!(
            c.next_message()
                .await
                .unwrap()
                .is(Kind::Response, "control", "hello")
        );
    }

    #[tokio::test]
    async fn accept_rejects_wrong_key_and_non_hello() {
        let (a, b) = duplex(1 << 22);
        let (acc, ctl) = keys();
        let mut c = HdsConn::new(b, ctl.clone());
        ctl_send(
            &mut c,
            "request",
            "control",
            "hello",
            1,
            DsValue::Dict(vec![]),
        )
        .await;
        let wrong = HdsKeys::derive(&[9; 32], &[1; 32], &[2; 32]);
        assert!(HdsConn::accept(a, &[wrong]).await.is_err());

        let (a, b) = duplex(1 << 22);
        let mut c = HdsConn::new(b, ctl);
        ctl_send(
            &mut c,
            "request",
            "dataSend",
            "open",
            1,
            DsValue::Dict(vec![]),
        )
        .await;
        assert!(HdsConn::accept(a, &[acc]).await.is_err());
    }
}
