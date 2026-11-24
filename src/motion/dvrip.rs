//! Minimal DVRIP client (TCP 34567): login + GUARD_REQ and reading of alarms 1504.
//! References: go2rtc `pkg/dvrip/client.go`, python-dvr `dvrip.py`.
use std::time::Duration;

use anyhow::{Context, Result, bail};
use md5::{Digest, Md5};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch};
use tokio::time::{Instant, sleep_until};

use crate::redact::redact;

const LOGIN: u16 = 1000;
const KEEPALIVE: u16 = 1006;
const GUARD_REQ: u16 = 1500;
const ALARM_REQ: u16 = 1504;
const KEEPALIVE_EVERY: Duration = Duration::from_secs(20);

pub fn sofia_hash(password: &str) -> String {
    const CHARS: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let h = Md5::digest(password.as_bytes());
    h.chunks(2)
        .map(|p| CHARS[(u16::from(p[0]) + u16::from(p[1])) as usize % 62] as char)
        .collect()
}

/// 20-byte header: 0xFF, version, 2 bytes of padding, session u32, sequence u32,
/// 2 bytes of padding, msgid u16, length u32 (all little-endian).
#[derive(Debug, PartialEq)]
pub struct Header {
    pub session: u32,
    pub seq: u32,
    pub cmd: u16,
    pub len: u32,
}

impl Header {
    pub fn encode(&self) -> [u8; 20] {
        let mut b = [0u8; 20];
        b[0] = 0xFF;
        b[4..8].copy_from_slice(&self.session.to_le_bytes());
        b[8..12].copy_from_slice(&self.seq.to_le_bytes());
        b[14..16].copy_from_slice(&self.cmd.to_le_bytes());
        b[16..20].copy_from_slice(&self.len.to_le_bytes());
        b
    }

    pub fn decode(b: &[u8; 20]) -> Result<Header> {
        if b[0] != 0xFF {
            bail!("invalid DVRIP header");
        }
        Ok(Header {
            session: u32::from_le_bytes(b[4..8].try_into().unwrap()),
            seq: u32::from_le_bytes(b[8..12].try_into().unwrap()),
            cmd: u16::from_le_bytes(b[14..16].try_into().unwrap()),
            len: u32::from_le_bytes(b[16..20].try_into().unwrap()),
        })
    }
}

/// `Some(true)` = Start, `Some(false)` = Stop; `None` if it is not a motion event.
/// Lenient: any Event containing "Motion" (also "HumanDetect"); unknown events
/// are logged (name only).
pub fn parse_alarm(json: &Value) -> Option<bool> {
    let info = json.get("AlarmInfo")?;
    let event = info.get("Event")?.as_str()?;
    let status = info.get("Status").and_then(Value::as_str).unwrap_or("");
    tracing::info!("DVRIP alarm: event={event} status={status}");
    if !(event.contains("Motion") || event.contains("HumanDetect")) {
        return None;
    }
    match status.to_ascii_lowercase().as_str() {
        "start" => Some(true),
        "stop" => Some(false),
        _ => None,
    }
}

struct Target {
    addr: String,
    user: String,
    pass: String,
}

fn parse_url(url: &str) -> Result<Target> {
    let u = url::Url::parse(url).map_err(|_| anyhow::anyhow!("invalid motion URL"))?;
    let dec = |s: &str| {
        percent_encoding::percent_decode_str(s)
            .decode_utf8_lossy()
            .into_owned()
    };
    let host = u.host_str().context("motion URL has no host")?;
    Ok(Target {
        addr: format!("{host}:{}", u.port().unwrap_or(34567)),
        user: dec(u.username()),
        pass: dec(u.password().unwrap_or("")),
    })
}

pub fn spawn(url: &str, hold: Duration) -> Result<watch::Receiver<bool>> {
    let target = parse_url(url)?;
    let label = redact(url);
    let (tx, rx) = watch::channel(false);
    let (ev_tx, ev_rx) = mpsc::channel(16);
    tokio::spawn(drive(ev_rx, tx, hold));
    tokio::spawn(async move {
        let mut backoff = Duration::from_secs(1);
        loop {
            let res = session(&target, &ev_tx, &mut backoff).await;
            let _ = ev_tx.send(false).await;
            match res {
                // The error never includes the URL or the key.
                Err(e) => tracing::warn!(url = %label, "DVRIP motion down: {e:#}"),
                Ok(()) => tracing::warn!(url = %label, "DVRIP motion closed"),
            }
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(Duration::from_secs(30));
        }
    });
    Ok(rx)
}

/// Applies the events to the channel. Any alarm (Start or Stop) sets `true` and re-arms the deadline:
/// it returns to `false` `hold` after the LAST one. The camera emits Start/Stop ~1 s apart, an event
/// too short for HKSV.
async fn drive(mut events: mpsc::Receiver<bool>, tx: watch::Sender<bool>, hold: Duration) {
    let mut deadline: Option<Instant> = None;
    loop {
        tokio::select! {
            ev = events.recv() => match ev {
                Some(_) => { deadline = Some(Instant::now() + hold); tx.send_replace(true); }
                None => return,
            },
            _ = async { sleep_until(deadline.unwrap()).await }, if deadline.is_some() => {
                deadline = None;
                tx.send_replace(false);
            }
        }
    }
}

async fn send(
    w: &mut (impl AsyncWriteExt + Unpin),
    session: u32,
    seq: &mut u32,
    cmd: u16,
    body: &str,
) -> Result<()> {
    let mut payload = body.as_bytes().to_vec();
    payload.extend_from_slice(b"\x0a\x00");
    let h = Header {
        session,
        seq: *seq,
        cmd,
        len: payload.len() as u32,
    };
    *seq += 1;
    w.write_all(&[&h.encode()[..], &payload].concat()).await?;
    Ok(())
}

async fn read_msg(r: &mut (impl AsyncReadExt + Unpin)) -> Result<(Header, Value)> {
    let mut hb = [0u8; 20];
    r.read_exact(&mut hb).await?;
    let h = Header::decode(&hb)?;
    if h.len > 1 << 20 {
        bail!("DVRIP message too large");
    }
    let mut body = vec![0u8; h.len as usize];
    r.read_exact(&mut body).await?;
    let json = serde_json::from_slice(body.strip_suffix(b"\x0a\x00").unwrap_or(&body))
        .unwrap_or(Value::Null);
    Ok((h, json))
}

async fn session(t: &Target, events: &mpsc::Sender<bool>, backoff: &mut Duration) -> Result<()> {
    let stream = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(&t.addr))
        .await
        .context("connect timeout")?
        .context("connection refused")?;
    let (mut rd, mut wr) = stream.into_split();
    let mut seq = 0u32;
    let login = json!({"EncryptType":"MD5","LoginType":"DVRIP-Web","PassWord":sofia_hash(&t.pass),"UserName":t.user});
    send(&mut wr, 0, &mut seq, LOGIN, &login.to_string()).await?;
    let (h, res) = tokio::time::timeout(Duration::from_secs(5), read_msg(&mut rd))
        .await
        .context("login timeout")??;
    if res.get("Ret").and_then(Value::as_i64) != Some(100) {
        bail!(
            "login rechazado (Ret={})",
            res.get("Ret").unwrap_or(&Value::Null)
        );
    }
    let session = h.session;
    let sid = format!("0x{session:08X}");
    send(
        &mut wr,
        session,
        &mut seq,
        GUARD_REQ,
        &json!({"Name":"","SessionID":sid}).to_string(),
    )
    .await?;
    tracing::info!("DVRIP motion connected");
    *backoff = Duration::from_secs(1);

    // Reading in a separate task: read_exact is not cancel-safe inside a select with the keepalive.
    let (msg_tx, mut msg_rx) = mpsc::channel(16);
    let reader = tokio::spawn(async move {
        loop {
            let m = read_msg(&mut rd).await;
            let stop = m.is_err();
            if msg_tx.send(m).await.is_err() || stop {
                return;
            }
        }
    });
    let mut tick = tokio::time::interval(KEEPALIVE_EVERY);
    tick.tick().await;
    let res = async {
        loop {
            tokio::select! {
                _ = tick.tick() => {
                    send(&mut wr, session, &mut seq, KEEPALIVE, &json!({"Name":"KeepAlive","SessionID":sid}).to_string()).await?;
                }
                m = msg_rx.recv() => {
                    let (h, json) = m.context("reader ended")??;
                    tracing::debug!("DVRIP msg {}", h.cmd);
                    if h.cmd == ALARM_REQ && let Some(on) = parse_alarm(&json) {
                        let _ = events.send(on).await;
                    }
                }
            }
        }
    }
    .await;
    reader.abort();
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sofia_hash_known_vector() {
        assert_eq!(sofia_hash(""), "tlJwpbo6");
        assert_eq!(sofia_hash("admin"), "6QNMIQGe");
    }

    #[test]
    fn header_roundtrip() {
        let h = Header {
            session: 0xd7,
            seq: 3,
            cmd: 1500,
            len: 42,
        };
        let b = h.encode();
        assert_eq!(b[0], 0xFF);
        assert_eq!(Header::decode(&b).unwrap(), h);
        assert!(Header::decode(&[0; 20]).is_err());
    }

    #[test]
    fn parse_alarm_start_stop() {
        let f = |s: &str| parse_alarm(&serde_json::from_str(s).unwrap());
        let start = r#"{"AlarmInfo":{"Channel":0,"Event":"VideoMotion","StartTime":"2026-11-23 10:00:00","Status":"Start"},"Name":"AlarmInfo","Ret":100,"SessionID":"0x000000D7"}"#;
        assert_eq!(f(start), Some(true));
        assert_eq!(f(&start.replace("Start\"}", "Stop\"}")), Some(false));
        assert_eq!(f(&start.replace("Start\"}", "start\"}")), Some(true));
        assert_eq!(f(&start.replace("VideoMotion", "HumanDetect")), Some(true));
        // Real name observed on the camera (iCSee).
        assert_eq!(
            f(&start.replace("VideoMotion", "appEventHumanDetectAlarm")),
            Some(true)
        );
        assert_eq!(f(&start.replace("VideoMotion", "VideoBlind")), None);
        assert_eq!(f(r#"{"Name":"KeepAlive","Ret":100}"#), None);
    }

    #[test]
    fn url_decodes_userinfo() {
        let t = parse_url("dvrip://admin:p%40ss@10.0.0.5:34567").unwrap();
        assert_eq!(
            (t.addr.as_str(), t.user.as_str(), t.pass.as_str()),
            ("10.0.0.5:34567", "admin", "p@ss")
        );
    }

    #[tokio::test(start_paused = true)]
    async fn motion_holds_10s_after_last_alarm() {
        let (tx, mut rx) = watch::channel(false);
        let (ev, evrx) = mpsc::channel(4);
        tokio::spawn(drive(evrx, tx, Duration::from_secs(10)));
        ev.send(true).await.unwrap();
        rx.changed().await.unwrap();
        assert!(*rx.borrow());
        // A Stop at +1 s does not turn it off: the deadline counts from the last alarm (Start or Stop).
        tokio::time::sleep(Duration::from_secs(1)).await;
        ev.send(false).await.unwrap();
        tokio::time::sleep(Duration::from_secs(9)).await;
        assert!(
            *rx.borrow(),
            "+10 s after Start but +9 s after the last Stop"
        );
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert!(!*rx.borrow());
    }

    /// Listens for ~90 s and logs each message; requires SPIKE_DVRIP_URL.
    #[tokio::test]
    #[ignore]
    async fn live_listen_90s() {
        let _ = tracing_subscriber::fmt()
            .with_env_filter("hksv_rtsp_bridge=debug")
            .try_init();
        let url = std::env::var("SPIKE_DVRIP_URL").unwrap();
        let t = parse_url(&url).unwrap();
        let (ev, mut evrx) = mpsc::channel(16);
        let mut backoff = Duration::from_secs(1);
        let run = session(&t, &ev, &mut backoff);
        let _ = tokio::time::timeout(Duration::from_secs(90), async {
            tokio::select! { r = run => r.map(|_| ()), _ = async { while let Some(e) = evrx.recv().await { println!("EVENT motion={e}"); } } => Ok(()) }
        }).await;
    }
}
