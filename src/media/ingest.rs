//! Always-open RTSP connection. Publishes video (Annex B) and PCMA audio via `broadcast`
//! and keeps a `Ring` with the prebuffer.
//!
//! - A slow receiver gets `RecvError::Lagged` and must re-subscribe (`subscribe`).
//! - When the connection is lost, the `Sender` is replaced: receivers get
//!   `RecvError::Closed` and sessions must end and re-subscribe.
//! - The pts resets on each RTSP session; the ring is emptied on reconnect.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use anyhow::{Context, Result};
use bytes::{BufMut, Bytes, BytesMut};
use futures::StreamExt;
use retina::client::{
    InitialTimestampPolicy, PlayOptions, Session, SessionIdPolicy, SessionOptions, SetupOptions,
    TcpTransportOptions, Transport,
};
use retina::codec::{CodecItem, FrameFormat, ParametersRef};
use tokio::sync::broadcast;

use super::ring::Ring;
use super::{AudioPacket, Codec, Frame, StreamInfo};
use crate::redact::redact;

const CHANNEL_CAP: usize = 256;
const FRAME_TIMEOUT: Duration = Duration::from_secs(10);

struct Inner {
    info: Mutex<Option<StreamInfo>>,
    connected: AtomicBool,
    codec: Mutex<Codec>,
    ring: Arc<RwLock<Ring>>,
    video: Mutex<broadcast::Sender<Frame>>,
    audio: Mutex<broadcast::Sender<AudioPacket>>,
}

#[derive(Clone)]
pub struct Stream(Arc<Inner>);

impl Stream {
    /// Spawns the ingest task (requires a tokio runtime).
    pub fn spawn(url: String, secs: u32) -> Stream {
        let inner = Arc::new(Inner {
            info: Mutex::new(None),
            connected: AtomicBool::new(false),
            codec: Mutex::new(Codec::default()),
            ring: Arc::new(RwLock::new(Ring::new(secs))),
            video: Mutex::new(broadcast::channel(CHANNEL_CAP).0),
            audio: Mutex::new(broadcast::channel(CHANNEL_CAP).0),
        });
        tokio::spawn(run(inner.clone(), url));
        Stream(inner)
    }

    /// Stream without an ingest task, for session tests.
    #[cfg(test)]
    pub fn detached() -> Stream {
        Self::detached_secs(5)
    }

    #[cfg(test)]
    pub fn detached_secs(secs: u32) -> Stream {
        Stream(Arc::new(Inner {
            info: Mutex::new(None),
            connected: AtomicBool::new(true),
            codec: Mutex::new(Codec::default()),
            ring: Arc::new(RwLock::new(Ring::new(secs))),
            video: Mutex::new(broadcast::channel(CHANNEL_CAP).0),
            audio: Mutex::new(broadcast::channel(CHANNEL_CAP).0),
        }))
    }

    /// Publishes a frame as ingest would (ring + broadcast).
    #[cfg(test)]
    pub fn push_frame(&self, frame: Frame) {
        let mut ring = self.0.ring.write().unwrap();
        ring.push(frame.clone());
        let _ = self.0.video.lock().unwrap().send(frame);
    }

    /// Simulates a camera drop: closes the current receivers.
    #[cfg(test)]
    pub fn disconnect(&self) {
        *self.0.video.lock().unwrap() = broadcast::channel(CHANNEL_CAP).0;
        *self.0.audio.lock().unwrap() = broadcast::channel(CHANNEL_CAP).0;
    }

    /// Last known info (kept while disconnected).
    pub fn info(&self) -> Option<StreamInfo> {
        self.0.info.lock().unwrap().clone()
    }

    /// Codec of the last connection (H.265 until the first one).
    pub fn codec(&self) -> Codec {
        *self.0.codec.lock().unwrap()
    }

    pub fn is_connected(&self) -> bool {
        self.0.connected.load(Ordering::Relaxed)
    }

    /// Backlog from the last keyframe + receiver with no gaps or duplicates.
    pub fn subscribe(&self) -> (Vec<Frame>, broadcast::Receiver<Frame>) {
        let ring = self.0.ring.read().unwrap(); // ingest sends while holding the write lock
        let rx = self.0.video.lock().unwrap().subscribe();
        (ring.from_last_keyframe(), rx)
    }

    /// Like `subscribe`, but the backlog starts at the keyframe covering the last
    /// `back_ticks` (90 kHz) of the ring.
    pub fn subscribe_back(&self, back_ticks: i64) -> (Vec<Frame>, broadcast::Receiver<Frame>) {
        let ring = self.0.ring.read().unwrap();
        let rx = self.0.video.lock().unwrap().subscribe();
        let backlog = ring
            .last_pts()
            .map_or(vec![], |last| ring.since(last - back_ticks));
        (backlog, rx)
    }

    pub fn subscribe_audio(&self) -> broadcast::Receiver<AudioPacket> {
        self.0.audio.lock().unwrap().subscribe()
    }

    pub fn ring(&self) -> Arc<RwLock<Ring>> {
        self.0.ring.clone()
    }

    pub fn latest_keyframe(&self) -> Option<Frame> {
        self.0.ring.read().unwrap().latest_keyframe()
    }
}

async fn run(inner: Arc<Inner>, url: String) {
    let mut backoff = Duration::from_secs(1);
    loop {
        let res = session(&inner, &url, &mut backoff).await;
        inner.connected.store(false, Ordering::Relaxed);
        // Closes the current receivers and empties the ring (pts resets).
        // All under a single write guard: a concurrent subscribe never sees old backlog with a new receiver.
        {
            let mut ring = inner.ring.write().unwrap();
            *inner.video.lock().unwrap() = broadcast::channel(CHANNEL_CAP).0;
            *inner.audio.lock().unwrap() = broadcast::channel(CHANNEL_CAP).0;
            ring.clear();
        }
        match res {
            Err(e) => {
                tracing::warn!(url = %redact(&url), "RTSP ingest down: {}", redact(&format!("{e:#}")))
            }
            Ok(()) => tracing::warn!(url = %redact(&url), "RTSP ingest ended (EOF)"),
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_secs(30));
    }
}

/// Positions of the parameter-set NAL units as (slot, NAL range without start code):
/// H.265 VPS/SPS/PPS (types 32..=34 -> slots 0..=2), H.264 SPS/PPS (types 7, 8 -> slots 1, 2).
fn param_sets(codec: Codec, data: &[u8]) -> Vec<(u8, std::ops::Range<usize>)> {
    let mut starts = vec![];
    let mut i = 0;
    while i + 3 < data.len() {
        if data[i..i + 3] == [0, 0, 1] {
            starts.push(i + 3);
            i += 3;
        } else {
            i += 1;
        }
    }
    let mut out = vec![];
    for (k, &s) in starts.iter().enumerate() {
        let mut e = starts.get(k + 1).map_or(data.len(), |n| n - 3);
        while e > s && data[e - 1] == 0 {
            e -= 1; // the extra 0 of a 4-byte start code
        }
        let slot = match codec {
            Codec::H265 => Some(((data[s] >> 1) & 0x3f).wrapping_sub(32)).filter(|t| *t <= 2),
            Codec::H264 => match data[s] & 0x1f {
                7 => Some(1),
                8 => Some(2),
                _ => None,
            },
        };
        if let Some(slot) = slot {
            out.push((slot, s..e));
        }
    }
    out
}

/// Keeps the latest VPS/SPS/PPS and prepends them to keyframes that lack them.
struct ParamCache {
    codec: Codec,
    sets: [Option<Bytes>; 3],
}

impl ParamCache {
    fn new(codec: Codec) -> Self {
        ParamCache {
            codec,
            sets: Default::default(),
        }
    }

    fn process(&mut self, data: &[u8], keyframe: bool) -> Bytes {
        let found = param_sets(self.codec, data);
        for (slot, r) in &found {
            self.sets[*slot as usize] = Some(Bytes::copy_from_slice(&data[r.clone()]));
        }
        // H.264 has no VPS: slot 0 stays empty and only SPS+PPS are needed.
        let need = if self.codec == Codec::H264 { 2 } else { 3 };
        if !keyframe || found.len() >= need || self.sets.iter().flatten().count() < need {
            return Bytes::copy_from_slice(data);
        }
        let mut b = BytesMut::new();
        for p in self.sets.iter().flatten() {
            b.put_slice(&[0, 0, 0, 1]);
            b.put_slice(p);
        }
        b.put_slice(data);
        b.freeze()
    }
}

async fn session(inner: &Inner, url: &str, backoff: &mut Duration) -> Result<()> {
    let parsed = url::Url::parse(url).context("invalid RTSP URL")?;
    // Some cameras (H.264 firmware) answer each SETUP with a different Session id: keep the first.
    let opts = SessionOptions::default().session_id(SessionIdPolicy::UseFirst);
    let mut s = Session::describe(parsed, opts).await?;
    let vi = s
        .streams()
        .iter()
        .position(|s| s.media() == "video")
        .context("no video stream")?;
    let codec = match s.streams()[vi].encoding_name() {
        "h264" => Codec::H264,
        "h265" => Codec::H265,
        other => anyhow::bail!("unsupported video codec {other:?}"),
    };
    *inner.codec.lock().unwrap() = codec;
    let ai = s
        .streams()
        .iter()
        .position(|s| s.media() == "audio" && s.encoding_name().eq_ignore_ascii_case("pcma"));
    let opts = || SetupOptions::default().transport(Transport::Tcp(TcpTransportOptions::default()));
    s.setup(vi, opts().frame_format(FrameFormat::SIMPLE))
        .await?;
    if let Some(ai) = ai {
        s.setup(ai, opts()).await?;
    }
    let has_audio = ai.is_some();
    // Permissive: the camera does not send rtptime in the audio stream's PLAY.
    let play = PlayOptions::default().initial_timestamp(InitialTimestampPolicy::Permissive);
    let mut d = s.play(play).await?.demuxed()?;
    tracing::info!(url = %redact(url), has_audio, "RTSP ingest connected");
    inner.connected.store(true, Ordering::Relaxed);

    let mut params = ParamCache::new(codec);
    let (mut n, mut first_ts, mut dims) = (0u64, 0i64, None);
    loop {
        let item = tokio::time::timeout(FRAME_TIMEOUT, d.next())
            .await
            .context("no RTSP data for 10 s")?;
        match item {
            None => return Ok(()),
            Some(Err(e)) => return Err(e.into()),
            Some(Ok(CodecItem::VideoFrame(f))) => {
                *backoff = Duration::from_secs(1); // frames are arriving: the connection is healthy
                let key = f.is_random_access_point();
                let pts = f.timestamp().timestamp();
                if n == 0 {
                    first_ts = pts;
                }
                n += 1;
                if key && let Some(ParametersRef::Video(v)) = d.streams()[vi].parameters() {
                    let (w, h) = v.pixel_dimensions();
                    dims = Some((w as u16, h as u16));
                }
                let frame = Frame {
                    pts90k: pts,
                    keyframe: key,
                    annexb: params.process(f.data(), key),
                };
                if let Some((width, height)) = dims
                    && n >= 2
                    && pts > first_ts
                    && (key || inner.info.lock().unwrap().is_none())
                {
                    let fps = (n - 1) as f32 * 90_000.0 / (pts - first_ts) as f32;
                    *inner.info.lock().unwrap() = Some(StreamInfo {
                        width,
                        height,
                        fps,
                        has_audio_alaw: has_audio,
                    });
                }
                let mut ring = inner.ring.write().unwrap();
                ring.push(frame.clone());
                let _ = inner.video.lock().unwrap().send(frame); // no receivers = Err, normal
            }
            Some(Ok(CodecItem::AudioFrame(a))) => {
                let _ = inner.audio.lock().unwrap().send(AudioPacket {
                    pts: a.timestamp().timestamp(),
                    alaw: Bytes::copy_from_slice(a.data()),
                });
            }
            Some(Ok(_)) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn param_cache_prepends_missing() {
        let mut c = ParamCache::new(Codec::H265);
        let kf1 = [
            &[0, 0, 0, 1, 0x40, 1, 9][..],
            &[0, 0, 0, 1, 0x42, 1, 8],
            &[0, 0, 0, 1, 0x44, 1, 7],
            &[0, 0, 1, 0x26, 1, 6],
        ]
        .concat();
        assert_eq!(c.process(&kf1, true), kf1);
        let kf2 = [0, 0, 1, 0x26, 1, 5];
        let out = c.process(&kf2, true);
        assert_eq!(param_sets(Codec::H265, &out).len(), 3);
        assert!(out.ends_with(&kf2));
        assert_eq!(c.process(&kf2, false), kf2.to_vec()); // P-frames left intact
    }

    #[test]
    fn param_cache_h264_prepends_sps_pps() {
        let mut c = ParamCache::new(Codec::H264);
        let kf1 = [
            &[0, 0, 0, 1, 0x67, 1][..], // SPS
            &[0, 0, 0, 1, 0x68, 2],     // PPS
            &[0, 0, 1, 0x65, 3],        // IDR
        ]
        .concat();
        assert_eq!(c.process(&kf1, true), kf1);
        let kf2 = [0, 0, 1, 0x65, 4];
        let out = c.process(&kf2, true);
        assert_eq!(param_sets(Codec::H264, &out).len(), 2);
        assert!(out.ends_with(&kf2));
        assert!(Codec::H264.has_idr(&kf2) && !Codec::H264.has_idr(&[0, 0, 1, 0x41, 1]));
    }

    fn live_url() -> String {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
        std::env::var("SPIKE_RTSP_URL").expect("SPIKE_RTSP_URL")
    }

    async fn wait_info(s: &Stream, secs: u64) -> StreamInfo {
        for _ in 0..secs * 10 {
            if let Some(i) = s.info() {
                return i;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("no info in {secs} s");
    }

    #[tokio::test]
    #[ignore = "requiere SPIKE_RTSP_URL"]
    async fn ingest_receives_keyframe_live() {
        let s = Stream::spawn(live_url(), 8);
        let info = wait_info(&s, 10).await;
        assert_eq!((info.width, info.height), (640, 360));
        assert!(info.has_audio_alaw);
        let (_, mut rx) = s.subscribe();
        let kf = loop {
            let f = tokio::time::timeout(Duration::from_secs(10), rx.recv())
                .await
                .expect("keyframe within 10 s")
                .unwrap();
            if f.keyframe {
                break f;
            }
        };
        let types: Vec<u8> = param_sets(Codec::H265, &kf.annexb)
            .iter()
            .map(|p| p.0)
            .collect();
        assert_eq!(&types[..3], &[32, 33, 34]);
        assert!(kf.annexb.starts_with(&[0, 0, 0, 1, 0x40]));
        assert!(s.latest_keyframe().is_some());
        println!("info={info:?} keyframe_bytes={}", kf.annexb.len());
    }

    /// Local TCP proxy that can be "cut" to force a reconnect.
    #[tokio::test]
    #[ignore = "requiere SPIKE_RTSP_URL"]
    async fn ingest_reconnects() {
        let mut u = url::Url::parse(&live_url()).unwrap();
        let target = format!("{}:{}", u.host_str().unwrap(), u.port().unwrap_or(554));
        let lis = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = lis.local_addr().unwrap().port();
        let (kill, _) = broadcast::channel::<()>(1);
        let k = kill.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut c, _)) = lis.accept().await else {
                    return;
                };
                let target = target.clone();
                let mut kr = k.subscribe();
                tokio::spawn(async move {
                    let Ok(mut up) = tokio::net::TcpStream::connect(target).await else {
                        return;
                    };
                    tokio::select! {
                        _ = tokio::io::copy_bidirectional(&mut c, &mut up) => {}
                        _ = kr.recv() => {}
                    }
                });
            }
        });
        u.set_host(Some("127.0.0.1")).unwrap();
        u.set_port(Some(port)).unwrap();
        let s = Stream::spawn(u.to_string(), 8);
        wait_info(&s, 15).await;
        let (_, mut rx) = s.subscribe();
        kill.send(()).unwrap();
        // the receivers close...
        loop {
            match tokio::time::timeout(Duration::from_secs(15), rx.recv()).await {
                Ok(Err(broadcast::error::RecvError::Closed)) => break,
                Ok(_) => continue,
                Err(_) => panic!("receiver did not close"),
            }
        }
        // ...and video returns over a new connection
        let (_, mut rx2) = s.subscribe();
        tokio::time::timeout(Duration::from_secs(20), rx2.recv())
            .await
            .expect("no frames after reconnect")
            .unwrap();
        assert!(s.is_connected());
        assert!(s.info().is_some());
        println!("reconnected: info={:?}", s.info());
    }
}
