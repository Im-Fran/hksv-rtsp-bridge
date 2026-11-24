//! Classic HomeKit Secure Video (H.264 + AAC-LC in fMP4) over HDS `dataSend`.
//!
//! TLVs 205/206/207/209 per `RecordingManagement.ts` in HAP-NodeJS. Transcoding happens only
//! while a recording is in progress: an ffmpeg reads the HEVC from main (ring backlog + live) and the
//! A-law audio through a FIFO, and writes fMP4 to stdout. Here it is split by boxes (ftyp+moov = init,
//! moof+mdat = fragment) and sent over HDS.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, watch};
use tokio::time::Instant;
use uuid::Uuid;

use crate::hap::model::Accessory;
use crate::hap::tlv8::Tlv8;
use crate::hap::uuids as u;
use crate::hds::{DsValue, HdsConn, HdsServer, Kind, Message, reason};
use crate::media::ffmpeg::Ffmpeg;
use crate::media::ingest::Stream;
use crate::media::{Codec, Frame};

pub const PREBUFFER_MS: u32 = 8000;
pub const FRAGMENT_MS: u32 = 4000;
/// Safety cap: the hub decides when it ends (it closes the stream); if it does not, it is marked
/// endOfStream here (Scrypted uses an equivalent maximum).
const MAX_DURATION: Duration = Duration::from_secs(180);
const RECORDING_TYPE: &str = "ipcamera.recording";
/// (width, height, fps) advertised in 206.
const RESOLUTIONS: [(u16, u16, u8); 2] = [(1920, 1080, 30), (1280, 720, 30)];
/// 0 = 8 kHz, 1 = 16 kHz, 2 = 24 kHz, 3 = 32, 4 = 44.1, 5 = 48.
const AUDIO_RATES: [u8; 2] = [1, 2];

/// HAP-NodeJS TLV8 list: items of the same type separated by an empty type-0 TLV.
fn list(mut t: Tlv8, tag: u8, items: &[Vec<u8>]) -> Tlv8 {
    for (i, it) in items.iter().enumerate() {
        if i > 0 {
            t = t.push(0, &[]);
        }
        t = t.push(tag, it);
    }
    t
}

/// Supported Camera Recording Configuration (205): prebuffer, Motion trigger, and fMP4.
pub fn supported_camera_tlv() -> Vec<u8> {
    let container = Tlv8::new()
        .push_u8(1, 0) // fragmented MP4
        .push(2, &Tlv8::new().push(1, &FRAGMENT_MS.to_le_bytes()).encode())
        .encode();
    Tlv8::new()
        .push(1, &PREBUFFER_MS.to_le_bytes())
        .push_u64(2, 1) // bit 0 = Motion
        .push(3, &container)
        .encode()
}

/// Supported Video Recording Configuration (206): H.264 Main/High, levels 3.1/3.2/4.0.
pub fn supported_video_tlv() -> Vec<u8> {
    let params = list(Tlv8::new(), 1, &[vec![1], vec![2]]);
    let params = list(params, 2, &[vec![0], vec![1], vec![2]]).encode();
    let attrs: Vec<Vec<u8>> = RESOLUTIONS
        .iter()
        .map(|&(w, h, fps)| {
            Tlv8::new()
                .push(1, &w.to_le_bytes())
                .push(2, &h.to_le_bytes())
                .push_u8(3, fps)
                .encode()
        })
        .collect();
    let codec = list(Tlv8::new().push_u8(1, 0).push(2, &params), 3, &attrs).encode();
    Tlv8::new().push(1, &codec).encode()
}

/// Supported Audio Recording Configuration (207): AAC-LC mono, VBR, 16/24 kHz.
pub fn supported_audio_tlv() -> Vec<u8> {
    let rates: Vec<Vec<u8>> = AUDIO_RATES.iter().map(|&r| vec![r]).collect();
    let params = list(Tlv8::new().push_u8(1, 1).push_u8(2, 0), 3, &rates).encode();
    let codec = Tlv8::new().push_u8(1, 0).push(2, &params).encode();
    Tlv8::new().push(1, &codec).encode()
}

/// Selected Camera Recording Configuration (209), already parsed.
#[derive(Clone, Debug, PartialEq)]
pub struct Selected {
    pub prebuffer_ms: u32,
    pub fragment_ms: u32,
    pub width: u16,
    pub height: u16,
    pub fps: u8,
    /// 0 = Baseline, 1 = Main, 2 = High.
    pub profile: u8,
    /// 0 = 3.1, 1 = 3.2, 2 = 4.0.
    pub level: u8,
    pub video_kbps: u32,
    pub iframe_ms: u32,
    pub audio_hz: u32,
    pub audio_kbps: u32,
}

impl Default for Selected {
    /// First advertised option; used if the hub has not yet written 209 (e.g. after a restart).
    fn default() -> Self {
        Selected {
            prebuffer_ms: PREBUFFER_MS,
            fragment_ms: FRAGMENT_MS,
            width: RESOLUTIONS[0].0,
            height: RESOLUTIONS[0].1,
            fps: RESOLUTIONS[0].2,
            profile: 2,
            level: 2,
            video_kbps: 2000,
            iframe_ms: FRAGMENT_MS,
            audio_hz: 16_000,
            audio_kbps: 32,
        }
    }
}

impl Selected {
    pub fn parse(raw: &[u8]) -> Result<Selected> {
        let sub = |t: &Tlv8, k: u8, what: &str| -> Result<Tlv8> {
            Tlv8::parse(t.get(k).with_context(|| format!("209 missing {what}"))?)
        };
        let top = Tlv8::parse(raw)?;
        let rec = sub(&top, 1, "recording")?;
        let video = sub(&top, 2, "video")?;
        let audio = sub(&top, 3, "audio")?;
        let container = Tlv8::parse(rec.get(3).context("209 missing container")?)?;
        let cparams = sub(&container, 2, "container params")?;
        let vparams = sub(&video, 2, "video params")?;
        let vattrs = sub(&video, 3, "video attrs")?;
        let aparams = sub(&audio, 2, "audio params")?;
        let num = |t: &Tlv8, k: u8| -> Result<u32> {
            t.get_u32(k)?.with_context(|| format!("missing field {k}"))
        };
        let hz = match num(&aparams, 3)? {
            0 => 8_000,
            1 => 16_000,
            2 => 24_000,
            3 => 32_000,
            4 => 44_100,
            5 => 48_000,
            n => bail!("unknown audio rate {n}"),
        };
        Ok(Selected {
            prebuffer_ms: num(&rec, 1)?,
            fragment_ms: num(&cparams, 1)?,
            width: num(&vattrs, 1)? as u16,
            height: num(&vattrs, 2)? as u16,
            fps: num(&vattrs, 3)? as u8,
            profile: num(&vparams, 1)? as u8,
            level: num(&vparams, 2)? as u8,
            video_kbps: num(&vparams, 3)?,
            iframe_ms: num(&vparams, 4)?,
            audio_hz: hz,
            audio_kbps: num(&aparams, 4).unwrap_or(32),
        })
    }
}

/// ffmpeg arguments: HEVC Annex B via stdin (`fps` fixes the timestamps: the backlog enters more
/// quickly than real time), optional A-law via `audio_fifo`, fMP4 via stdout.
pub fn ffmpeg_args(
    codec: Codec,
    sel: &Selected,
    fps: f32,
    audio_fifo: Option<&Path>,
) -> Vec<String> {
    let mut a: Vec<String> = Vec::new();
    let mut add = |xs: &[&str]| a.extend(xs.iter().map(|s| s.to_string()));
    add(&["-probesize", "2000000", "-analyzeduration", "1000000"]);
    add(&[
        "-framerate",
        &format!("{fps:.3}"),
        "-f",
        codec.ffmpeg_fmt(),
        "-i",
        "pipe:0",
    ]);
    if let Some(f) = audio_fifo {
        add(&["-probesize", "32", "-analyzeduration", "0"]);
        add(&["-f", "alaw", "-ar", "8000", "-ac", "1", "-i"]);
        add(&[&f.to_string_lossy()]);
    }
    add(&["-map", "0:v:0"]);
    if audio_fifo.is_some() {
        add(&["-map", "1:a:0"]);
    }
    let profile = if sel.profile >= 2 { "high" } else { "main" };
    let level = ["3.1", "3.2", "4.0"][usize::from(sel.level.min(2))];
    let kbps = sel.video_kbps.max(500);
    let secs = (sel.iframe_ms.max(1000) as f32 / 1000.0).to_string();
    // Like Scrypted/homebridge-camera-ffmpeg: fps from the chosen config and no B-frames (no ctts nor
    // edit list: the hub is strict about the fMP4 timestamps).
    add(&[
        "-c:v",
        "libx264",
        "-preset",
        "veryfast",
        "-bf",
        "0",
        "-r",
        &sel.fps.max(1).to_string(),
    ]);
    add(&[
        "-profile:v",
        profile,
        "-level",
        level,
        "-pix_fmt",
        "yuv420p",
    ]);
    add(&["-vf", &format!("scale={}:{}", sel.width, sel.height)]);
    add(&["-b:v", &format!("{kbps}k"), "-maxrate", &format!("{kbps}k")]);
    add(&["-bufsize", &format!("{}k", kbps * 2)]);
    add(&["-force_key_frames", &format!("expr:gte(t,n_forced*{secs})")]);
    add(&["-x264-params", "scenecut=0"]);
    if audio_fifo.is_some() {
        add(&["-c:a", "aac", "-profile:a", "aac_low", "-ac", "1"]);
        add(&["-ar", &sel.audio_hz.to_string()]);
        add(&["-b:a", &format!("{}k", sel.audio_kbps.clamp(16, 64))]);
    }
    add(&["-movflags", "frag_keyframe+empty_moov+default_base_moof"]);
    add(&["-f", "mp4", "pipe:1"]);
    a
}

#[derive(Debug, PartialEq)]
pub enum Segment {
    /// ftyp + moov.
    Init(Vec<u8>),
    /// moof + mdat.
    Fragment(Vec<u8>),
}

/// Splits ffmpeg's fMP4 output into init and fragments by walking the top-level boxes.
#[derive(Default)]
pub struct Mp4Splitter {
    buf: Vec<u8>,
    init: Vec<u8>,
    frag: Vec<u8>,
}

impl Mp4Splitter {
    pub fn push(&mut self, data: &[u8]) -> Vec<Segment> {
        self.buf.extend_from_slice(data);
        let buf = std::mem::take(&mut self.buf);
        let (mut out, mut pos) = (Vec::new(), 0);
        while let Some(b) = buf.get(pos..).filter(|b| b.len() >= 8) {
            let (mut size, mut hdr) = (u32::from_be_bytes(b[..4].try_into().unwrap()) as usize, 8);
            if size == 1 {
                let Some(l) = b.get(8..16) else { break };
                size = u64::from_be_bytes(l.try_into().unwrap()) as usize;
                hdr = 16;
            }
            if size < hdr {
                return out; // corrupt (or size 0 = until EOF, which ffmpeg does not emit): discarded
            }
            if b.len() < size {
                break;
            }
            let bx = &b[..size];
            match &b[4..8] {
                b"ftyp" => self.init = bx.to_vec(),
                b"moov" => {
                    self.init.extend_from_slice(bx);
                    out.push(Segment::Init(std::mem::take(&mut self.init)));
                }
                b"moof" => self.frag = bx.to_vec(),
                b"mdat" if !self.frag.is_empty() => {
                    self.frag.extend_from_slice(bx);
                    out.push(Segment::Fragment(std::mem::take(&mut self.frag)));
                }
                _ => {}
            }
            pos += size;
        }
        self.buf = buf[pos..].to_vec();
        out
    }
}

/// An A-law FIFO (ffmpeg reads it as a second input). Removed on drop.
struct Fifo(PathBuf);

impl Fifo {
    fn new() -> Result<Fifo> {
        let p = std::env::temp_dir().join(format!(
            "hksv-rtsp-bridge-rec-{}-{:08x}.fifo",
            std::process::id(),
            rand::random::<u32>()
        ));
        let c = std::ffi::CString::new(p.to_string_lossy().as_bytes())?;
        // SAFETY: `c` is a valid C string and lives for the duration of the call.
        if unsafe { libc::mkfifo(c.as_ptr(), 0o600) } != 0 {
            return Err(std::io::Error::last_os_error()).context("mkfifo");
        }
        Ok(Fifo(p))
    }
}

impl Drop for Fifo {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// A-law silence (0xD5) to align the audio, which only exists from the open, with the end of the
/// video backlog.
const ALAW_SILENCE: u8 = 0xD5;

/// Serves a camera's HDS connections and records when the hub opens `dataSend`.
pub struct Recorder {
    pub main: Stream,
    pub motion: watch::Receiver<bool>,
    pub accessory: Arc<RwLock<Accessory>>,
    pub bin: Option<String>,
    pub max_duration: Duration,
    busy: AtomicBool,
}

struct BusyGuard<'a>(&'a AtomicBool);

impl Drop for BusyGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

impl Recorder {
    pub fn new(
        main: Stream,
        motion: watch::Receiver<bool>,
        accessory: Arc<RwLock<Accessory>>,
    ) -> Arc<Recorder> {
        Arc::new(Recorder {
            main,
            motion,
            accessory,
            bin: None,
            max_duration: MAX_DURATION,
            busy: AtomicBool::new(false),
        })
    }

    /// Takes the HDS server's connections (once) and serves them.
    pub fn start(self: &Arc<Self>, hds: &HdsServer) {
        let Some(mut rx) = hds.connections() else {
            return;
        };
        let me = self.clone();
        tokio::spawn(async move {
            while let Some(conn) = rx.recv().await {
                tokio::spawn(me.clone().handle_conn(conn));
            }
        });
    }

    fn value(&self, svc: Uuid, ch: Uuid) -> Option<Value> {
        let acc = self.accessory.read().unwrap();
        acc.services
            .iter()
            .filter(|s| s.ty == svc)
            .flat_map(|s| &s.chars)
            .find(|c| c.ty == ch)
            .map(|c| c.value.clone())
    }

    fn flag(&self, svc: Uuid, ch: Uuid) -> bool {
        self.value(svc, ch).is_some_and(|v| {
            v.as_bool()
                .unwrap_or_else(|| v.as_u64().is_some_and(|n| n != 0))
        })
    }

    fn selected(&self) -> Selected {
        self.value(
            u::CAMERA_EVENT_RECORDING_MANAGEMENT,
            u::SELECTED_CAMERA_RECORDING_CONFIG,
        )
        .and_then(|v| B64.decode(v.as_str()?).ok())
        .and_then(|raw| match Selected::parse(&raw) {
            Ok(s) => Some(s),
            Err(e) if !raw.is_empty() => {
                tracing::warn!("recording: invalid 209 ({e:#}), using default config");
                None
            }
            Err(_) => None,
        })
        .unwrap_or_default()
    }

    /// Frames to transcode on open: starting from the keyframe that covers `prebuffer_ms`.
    fn backlog(&self, sel: &Selected) -> (Vec<Frame>, tokio::sync::broadcast::Receiver<Frame>) {
        self.main
            .subscribe_back(i64::from(sel.prebuffer_ms.min(PREBUFFER_MS)) * 90)
    }

    pub async fn handle_conn<S: AsyncRead + AsyncWrite + Unpin>(
        self: Arc<Self>,
        mut conn: HdsConn<S>,
    ) {
        while let Ok(msg) = conn.next_message().await {
            tracing::info!(
                "HDS hub -> {:?} {}/{} id={:?} body={:?}{}",
                msg.kind,
                msg.protocol,
                msg.topic,
                msg.id,
                msg.body,
                reason_note(&msg)
            );
            let Some(req) = msg.as_data_send_open() else {
                continue;
            };
            let refuse = if req.type_ != RECORDING_TYPE || req.target != "controller" {
                Some(reason::UNEXPECTED_FAILURE)
            // ponytail: Active (204) is not required: after a restart it goes back to 0 and the hub does not always
            // rewrite it; if it opens a dataSend, recording is enabled.
            } else if !self.flag(u::CAMERA_OPERATING_MODE, u::HOMEKIT_CAMERA_ACTIVE) {
                Some(reason::NOT_ALLOWED)
            } else {
                None
            };
            if let Some(why) = refuse {
                if conn.reject_open(&req, why).await.is_err() {
                    return;
                }
                continue;
            }
            if self.busy.swap(true, Ordering::AcqRel) {
                tracing::info!("recording: one already in progress, rejecting open");
                if conn.reject_open(&req, reason::BUSY).await.is_err() {
                    return;
                }
                continue;
            }
            let _guard = BusyGuard(&self.busy);
            if conn.accept_open(&req).await.is_err() {
                return;
            }
            tracing::info!(reason = ?req.reason, "recording: dataSend open");
            match self.record(&mut conn, req.stream_id).await {
                Ok(()) => tracing::info!("recording: finished"),
                Err(e) => {
                    tracing::warn!("recording: {e:#}");
                    let _ = conn
                        .send_close(req.stream_id, reason::UNEXPECTED_FAILURE)
                        .await;
                }
            }
        }
    }

    async fn record<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        conn: &mut HdsConn<S>,
        sid: i64,
    ) -> Result<()> {
        let t0 = Instant::now();
        let sel = self.selected();
        tracing::info!("recording: effective 209 {sel:?}");
        let info = self.main.info();
        let fps = info.as_ref().map_or(25.0, |i| i.fps.clamp(5.0, 60.0));
        let want_audio = self.flag(
            u::CAMERA_EVENT_RECORDING_MANAGEMENT,
            u::RECORDING_AUDIO_ACTIVE,
        ) && info.is_some_and(|i| i.has_audio_alaw);
        let fifo = want_audio.then(Fifo::new).transpose()?;
        let args = ffmpeg_args(
            self.main.codec(),
            &sel,
            fps,
            fifo.as_ref().map(|f| f.0.as_path()),
        );
        tracing::info!(
            "recording: camera fps {fps:.1}, audio={}, ffmpeg {}",
            fifo.is_some(),
            args.join(" ")
        );
        let mut ff = match &self.bin {
            Some(b) => Ffmpeg::spawn_bin(b, args)?,
            None => Ffmpeg::spawn(args)?,
        };
        let stdin = ff.take_stdin().context("ffmpeg has no stdin")?;
        let mut stdout = ff.take_stdout().context("ffmpeg has no stdout")?;

        let (backlog, mut vrx) = self.backlog(&sel);
        let silence = backlog.first().zip(backlog.last()).map_or(0, |(a, b)| {
            ((b.pts90k - a.pts90k).max(0) as usize / 90 * 8) & !1 // 8 samples per ms
        });
        let main = self.main.clone();
        let video = tokio::spawn(async move {
            use tokio::sync::broadcast::error::RecvError;
            let mut stdin = stdin;
            for f in &backlog {
                stdin.write_all(&f.annexb).await?;
            }
            loop {
                match vrx.recv().await {
                    Ok(f) => stdin.write_all(&f.annexb).await?,
                    Err(RecvError::Lagged(n)) => {
                        // Ffmpeg can't keep up: skip to the last keyframe.
                        tracing::warn!(
                            "recording: video lagging ({n} frames), skipping to last keyframe"
                        );
                        let (b, r) = main.subscribe();
                        vrx = r;
                        for f in &b {
                            stdin.write_all(&f.annexb).await?;
                        }
                    }
                    Err(RecvError::Closed) => return anyhow::Ok(()),
                }
            }
        });
        let audio = match &fifo {
            Some(f) => {
                let mut arx = self.main.subscribe_audio();
                // read_write: does not block waiting for the reader (ffmpeg opens it later).
                let file = std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(&f.0)?;
                let mut tx = tokio::net::unix::pipe::Sender::from_file(file)?;
                Some(tokio::spawn(async move {
                    tx.write_all(&vec![ALAW_SILENCE; silence]).await?;
                    loop {
                        match arx.recv().await {
                            Ok(p) => tx.write_all(&p.alaw).await?,
                            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                            Err(_) => return anyhow::Ok(()),
                        }
                    }
                }))
            }
            None => None,
        };
        let (seg_tx, mut seg_rx) = mpsc::channel::<Segment>(16);
        let reader = tokio::spawn(async move {
            let (mut sp, mut buf) = (Mp4Splitter::default(), vec![0u8; 64 * 1024]);
            while let Ok(n) = stdout.read(&mut buf).await {
                if n == 0 {
                    break;
                }
                for s in sp.push(&buf[..n]) {
                    if seg_tx.send(s).await.is_err() {
                        return;
                    }
                }
            }
        });

        let result = self.pump(conn, sid, &mut seg_rx, t0).await;
        // End: EOF to ffmpeg (stdin and FIFO), drain what remains, and send the last one with endOfStream.
        video.abort();
        if let Some(a) = &audio {
            a.abort();
        }
        let result = match result {
            Ok(Some(held)) => self.finish(conn, sid, &mut seg_rx, held).await,
            other => other.map(|_| ()),
        };
        reader.abort();
        drop(ff);
        result
    }

    /// Sends init and fragments (without retaining any) until the hub closes (`Ok(None)`) or
    /// the duration cap is reached or ffmpeg exits (`Ok(Some(..))`).
    async fn pump<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        conn: &mut HdsConn<S>,
        sid: i64,
        segs: &mut mpsc::Receiver<Segment>,
        t0: Instant,
    ) -> Result<Option<Held>> {
        let mut motion = self.motion.clone();
        let end_at = t0 + self.max_duration;
        let mut held = Held {
            seq: 1,
            frag: None,
            ts: Vec::new(),
        };
        loop {
            tokio::select! {
                s = segs.recv() => match s {
                    Some(Segment::Init(b)) => {
                        held.ts = inspect::init_timescales(&b);
                        tracing::info!(
                            "recording: init {} bytes at {:?}: {}",
                            b.len(),
                            t0.elapsed(),
                            inspect::describe_init(&b)
                        );
                        conn.send_data(sid, "mediaInitialization", held.seq, &b, false).await?;
                        held.seq += 1;
                    }
                    Some(Segment::Fragment(f)) => {
                        tracing::info!(
                            "recording: fragment seq={} {} bytes at {:?}: {}",
                            held.seq,
                            f.len(),
                            t0.elapsed(),
                            inspect::describe_fragment(&f, &held.ts)
                        );
                        conn.send_data(sid, "mediaFragment", held.seq, &f, false).await?;
                        held.seq += 1;
                    }
                    None => {
                        tracing::info!("recording: ended by ffmpeg (stdout closed) at {:?}", t0.elapsed());
                        return Ok(Some(held));
                    }
                },
                m = conn.next_message() => {
                    let m = m?;
                    tracing::info!(
                        "recording: hub -> {:?} {}/{} id={:?} status={:?} body={:?}{}",
                        m.kind, m.protocol, m.topic, m.id, m.status, m.body, reason_note(&m)
                    );
                    if m.is(Kind::Event, "dataSend", "close") && m.stream_id() == Some(sid) {
                        tracing::info!("recording: ended because hub closed the stream");
                        return Ok(None);
                    }
                    if let Some(r) = m.as_data_send_open() {
                        conn.reject_open(&r, reason::BUSY).await?;
                    }
                }
                _ = async {
                    if motion.changed().await.is_err() {
                        std::future::pending::<()>().await;
                    }
                } => {
                    // Informational only: the hub decides the end (it closes the stream).
                    let on = *motion.borrow_and_update();
                    tracing::info!("recording: motion={on} at {:?}", t0.elapsed());
                }
                _ = tokio::time::sleep_until(end_at) => {
                    tracing::info!("recording: ended by cap of {:?} at {:?}", self.max_duration, t0.elapsed());
                    return Ok(Some(held));
                }
            }
        }
    }

    async fn finish<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        conn: &mut HdsConn<S>,
        sid: i64,
        segs: &mut mpsc::Receiver<Segment>,
        mut held: Held,
    ) -> Result<()> {
        // ffmpeg has already seen EOF and flushes the last (partial) fragment. One is held back so it can
        // mark the last one with endOfStream.
        let drain = async {
            while let Some(s) = segs.recv().await {
                if let Segment::Fragment(f) = s {
                    tracing::info!(
                        "recording: final fragment {} bytes: {}",
                        f.len(),
                        inspect::describe_fragment(&f, &held.ts)
                    );
                    if let Some(prev) = held.frag.replace(f) {
                        conn.send_data(sid, "mediaFragment", held.seq, &prev, false)
                            .await?;
                        held.seq += 1;
                    }
                }
            }
            anyhow::Ok(())
        };
        if tokio::time::timeout(Duration::from_secs(10), drain)
            .await
            .is_err()
        {
            tracing::warn!("recording: ffmpeg did not finish in time");
        }
        match held.frag.take() {
            Some(last) => {
                tracing::info!("recording: last fragment seq={} with endOfStream", held.seq);
                conn.send_data(sid, "mediaFragment", held.seq, &last, true)
                    .await?;
            }
            None => tracing::warn!("recording: no final fragment to mark endOfStream"),
        }
        // The hub should close or confirm (HAP-NodeJS waits 12 s before forcing the close).
        let wait_close = async {
            loop {
                let m = conn.next_message().await?;
                tracing::info!(
                    "recording: hub -> {:?} {}/{} body={:?}{}",
                    m.kind,
                    m.protocol,
                    m.topic,
                    m.body,
                    reason_note(&m)
                );
                if m.is(Kind::Event, "dataSend", "close") && m.stream_id() == Some(sid) {
                    return anyhow::Ok(true);
                }
            }
        };
        match tokio::time::timeout(Duration::from_secs(12), wait_close).await {
            Ok(Ok(_)) => tracing::info!("recording: hub closed after endOfStream"),
            Ok(Err(e)) => {
                tracing::info!("recording: HDS connection ended after endOfStream: {e:#}")
            }
            Err(_) => {
                tracing::info!("recording: hub did not close within 12 s, closing ourselves");
                conn.send_close(sid, reason::NORMAL).await?;
            }
        }
        Ok(())
    }
}

/// Name of a message's numeric `reason` (HDSProtocolSpecificErrorReason in HAP-NodeJS).
fn reason_note(m: &Message) -> String {
    let name = match m.body.get("reason").and_then(DsValue::as_int) {
        Some(0) => "NORMAL",
        Some(1) => "NOT_ALLOWED",
        Some(2) => "BUSY",
        Some(3) => "CANCELLED",
        Some(4) => "UNSUPPORTED",
        Some(5) => "UNEXPECTED_FAILURE",
        Some(6) => "TIMEOUT",
        Some(7) => "BAD_DATA",
        Some(8) => "PROTOCOL_ERROR",
        Some(9) => "INVALID_CONFIGURATION",
        _ => return String::new(),
    };
    format!(" [reason={name}]")
}

struct Held {
    /// Next dataSequenceNumber (init = 1, fragments start at 2).
    seq: i64,
    frag: Option<Vec<u8>>,
    /// timescale per track_ID (from init), used to describe fragments.
    ts: Vec<(u32, u32)>,
}

/// Human-readable description of init/fragments for the logs (diagnostics against the hub).
mod inspect {
    /// Child boxes (type, payload) of a box buffer.
    fn boxes(mut b: &[u8]) -> Vec<([u8; 4], &[u8])> {
        let mut v = Vec::new();
        while b.len() >= 8 {
            let size = u32::from_be_bytes(b[..4].try_into().unwrap()) as usize;
            if size < 8 || size > b.len() {
                break;
            }
            v.push((b[4..8].try_into().unwrap(), &b[8..size]));
            b = &b[size..];
        }
        v
    }

    fn find<'a>(b: &'a [u8], ty: &[u8; 4]) -> Option<&'a [u8]> {
        boxes(b).into_iter().find(|(t, _)| t == ty).map(|(_, p)| p)
    }

    fn path<'a>(b: &'a [u8], p: &[&[u8; 4]]) -> Option<&'a [u8]> {
        p.iter().try_fold(b, |b, t| find(b, t))
    }

    fn u32at(b: &[u8], o: usize) -> Option<u32> {
        Some(u32::from_be_bytes(b.get(o..o + 4)?.try_into().ok()?))
    }

    fn u64at(b: &[u8], o: usize) -> Option<u64> {
        Some(u64::from_be_bytes(b.get(o..o + 8)?.try_into().ok()?))
    }

    fn names(b: &[u8]) -> String {
        boxes(b)
            .iter()
            .map(|(t, p)| format!("{}({})", String::from_utf8_lossy(t), p.len() + 8))
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// (track_ID, timescale) for each trak in the moov.
    pub fn init_timescales(init: &[u8]) -> Vec<(u32, u32)> {
        let Some(moov) = find(init, b"moov") else {
            return vec![];
        };
        boxes(moov)
            .iter()
            .filter(|(t, _)| t == b"trak")
            .filter_map(|(_, trak)| {
                let tkhd = find(trak, b"tkhd")?;
                let id = u32at(tkhd, if tkhd[0] == 1 { 20 } else { 12 })?;
                let mdhd = path(trak, &[b"mdia", b"mdhd"])?;
                Some((id, u32at(mdhd, if mdhd[0] == 1 { 20 } else { 12 })?))
            })
            .collect()
    }

    pub fn describe_init(init: &[u8]) -> String {
        let mut out = names(init);
        if let Some(moov) = find(init, b"moov") {
            out += &format!(" moov[{}]", names(moov));
            for (t, trak) in boxes(moov) {
                if &t != b"trak" {
                    continue;
                }
                let id = find(trak, b"tkhd")
                    .and_then(|k| u32at(k, if k[0] == 1 { 20 } else { 12 }))
                    .unwrap_or(0);
                let hdlr = path(trak, &[b"mdia", b"hdlr"])
                    .and_then(|h| h.get(8..12))
                    .map(|h| String::from_utf8_lossy(h).into_owned())
                    .unwrap_or_default();
                let stsd = path(trak, &[b"mdia", b"minf", b"stbl", b"stsd"]);
                let entry = stsd.and_then(|s| boxes(s.get(8..)?).into_iter().next());
                let detail = entry.map_or(String::new(), |(ty, e)| {
                    let name = String::from_utf8_lossy(&ty).into_owned();
                    if hdlr == "vide" {
                        let wh = (e.get(24..26), e.get(26..28));
                        let (w, h) = match wh {
                            (Some(w), Some(h)) => (
                                u16::from_be_bytes([w[0], w[1]]),
                                u16::from_be_bytes([h[0], h[1]]),
                            ),
                            _ => (0, 0),
                        };
                        // avcC: version, profile_idc, compat, level_idc.
                        let avcc = e.get(78..).and_then(|r| find(r, b"avcC"));
                        let pl = avcc.map_or(String::new(), |a| {
                            format!(" profile_idc={} level_idc={}", a[1], a[3])
                        });
                        format!("{name} {w}x{h}{pl}")
                    } else {
                        let ch = e
                            .get(16..18)
                            .map_or(0, |c| u16::from_be_bytes([c[0], c[1]]));
                        let rate = u32at(e, 24).map_or(0, |r| r >> 16);
                        let esds = e.get(28..).and_then(|r| find(r, b"esds"));
                        format!(
                            "{name} ch={ch} rate={rate} esds={}",
                            esds.map_or(0, |x| x.len() + 8)
                        )
                    }
                });
                out += &format!(" | trak {id} {hdlr} {detail}");
            }
        }
        out
    }

    /// Per traf: track, baseMediaDecodeTime, sample count, duration, and whether the first sample is a sync sample.
    pub fn describe_fragment(frag: &[u8], ts: &[(u32, u32)]) -> String {
        let Some(moof) = find(frag, b"moof") else {
            return "no moof".into();
        };
        let mut out = vec![format!("cajas: {}", names(frag))];
        for (t, traf) in boxes(moof) {
            if &t != b"traf" {
                continue;
            }
            let (mut id, mut def_dur, mut def_flags, mut bmdt) = (0, 0, 0u32, None);
            if let Some(h) = find(traf, b"tfhd") {
                let fl = u32at(h, 0).unwrap_or(0) & 0xff_ffff;
                id = u32at(h, 4).unwrap_or(0);
                let mut o = 8;
                if fl & 1 != 0 {
                    o += 8;
                }
                if fl & 2 != 0 {
                    o += 4;
                }
                if fl & 8 != 0 {
                    def_dur = u32at(h, o).unwrap_or(0);
                    o += 4;
                }
                if fl & 0x10 != 0 {
                    o += 4;
                }
                if fl & 0x20 != 0 {
                    def_flags = u32at(h, o).unwrap_or(0);
                }
            }
            if let Some(d) = find(traf, b"tfdt") {
                bmdt = if d[0] == 1 {
                    u64at(d, 4)
                } else {
                    u32at(d, 4).map(u64::from)
                };
            }
            let (mut n, mut dur, mut first_flags) = (0u32, 0u64, None);
            if let Some(r) = find(traf, b"trun") {
                let fl = u32at(r, 0).unwrap_or(0) & 0xff_ffff;
                n = u32at(r, 4).unwrap_or(0);
                let mut o = 8;
                if fl & 1 != 0 {
                    o += 4;
                }
                if fl & 4 != 0 {
                    first_flags = u32at(r, o);
                    o += 4;
                }
                let per = [0x100, 0x200, 0x400, 0x800]
                    .iter()
                    .map(|f| if fl & f != 0 { 4 } else { 0 })
                    .collect::<Vec<usize>>();
                let stride: usize = per.iter().sum();
                for k in 0..n as usize {
                    let base = o + k * stride;
                    let d = if fl & 0x100 != 0 {
                        u32at(r, base).unwrap_or(0)
                    } else {
                        def_dur
                    };
                    dur += u64::from(d);
                    if k == 0 && first_flags.is_none() && fl & 0x400 != 0 {
                        first_flags = u32at(r, base + per[0] + per[1]);
                    }
                }
            }
            let flags = first_flags.unwrap_or(def_flags);
            let scale = ts.iter().find(|(i, _)| *i == id).map_or(1, |x| x.1.max(1));
            out.push(format!(
                "traf {id}: bmdt={} ({:.3}s) samples={n} dur={:.3}s first_sync={}",
                bmdt.unwrap_or(0),
                bmdt.unwrap_or(0) as f64 / f64::from(scale),
                dur as f64 / f64::from(scale),
                flags & 0x10000 == 0
            ));
        }
        out.join("; ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::camera::services::build_classic_accessory;
    use crate::config::MaxResolution;
    use crate::hds::{DsValue, HdsKeys, Message};
    use crate::media::StreamInfo;
    use tokio::io::{DuplexStream, duplex};

    #[test]
    fn camera_recording_tlv_has_prebuffer_and_fragment() {
        // HAP-NodeJS: prebuffer i32 | triggers u64 (Motion = 1) | container {fMP4, {fragment i32}}.
        assert_eq!(
            hex::encode(supported_camera_tlv()),
            concat!(
                "0104401f0000",
                "02080100000000000000",
                "030b",
                "010100",
                "02060104a00f0000"
            )
        );
    }

    #[test]
    fn video_recording_tlv_lists() {
        let t = Tlv8::parse(&supported_video_tlv()).unwrap();
        let codec = Tlv8::parse(t.get(1).unwrap()).unwrap();
        assert_eq!(codec.get_u8(1).unwrap(), Some(0)); // H.264
        // Main/High profiles and levels 3.1/3.2/4.0; items separated by an empty type-0 TLV.
        assert_eq!(
            hex::encode(codec.get(2).unwrap()),
            concat!(
                "010101", "0000", "010102", "020100", "0000", "020101", "0000", "020102"
            )
        );
        let attrs = codec.get_all(3);
        assert_eq!(attrs.len(), 2);
        let a = Tlv8::parse(attrs[0]).unwrap();
        assert_eq!(a.get(1), Some(&1920u16.to_le_bytes()[..]));
        assert_eq!(a.get(2), Some(&1080u16.to_le_bytes()[..]));
        assert_eq!(a.get_u8(3).unwrap(), Some(30));
        let b = Tlv8::parse(attrs[1]).unwrap();
        assert_eq!(b.get(1), Some(&1280u16.to_le_bytes()[..]));
    }

    #[test]
    fn audio_recording_tlv_is_aac_lc_mono_16_24k() {
        let t = Tlv8::parse(&supported_audio_tlv()).unwrap();
        let codec = Tlv8::parse(t.get(1).unwrap()).unwrap();
        assert_eq!(codec.get_u8(1).unwrap(), Some(0)); // AAC-LC
        assert_eq!(
            hex::encode(codec.get(2).unwrap()),
            "010101020100030101000003 0102".replace(' ', "")
        );
    }

    /// 209 as the hub writes it (structure of `parseSelectedConfiguration` in HAP-NodeJS).
    fn selected_tlv() -> Vec<u8> {
        let rec = Tlv8::new()
            .push(1, &8000u32.to_le_bytes())
            .push_u64(2, 1)
            .push(
                3,
                &Tlv8::new()
                    .push_u8(1, 0)
                    .push(2, &Tlv8::new().push(1, &4000u32.to_le_bytes()).encode())
                    .encode(),
            )
            .encode();
        let video = Tlv8::new()
            .push_u8(1, 0)
            .push(
                2,
                &Tlv8::new()
                    .push_u8(1, 1)
                    .push_u8(2, 1)
                    .push(3, &1500u32.to_le_bytes())
                    .push(4, &4000u32.to_le_bytes())
                    .encode(),
            )
            .push(
                3,
                &Tlv8::new()
                    .push(1, &1280u16.to_le_bytes())
                    .push(2, &720u16.to_le_bytes())
                    .push_u8(3, 30)
                    .encode(),
            )
            .encode();
        let audio = Tlv8::new()
            .push_u8(1, 0)
            .push(
                2,
                &Tlv8::new()
                    .push_u8(1, 1)
                    .push_u8(2, 0)
                    .push_u8(3, 2)
                    .push(4, &24u32.to_le_bytes())
                    .encode(),
            )
            .encode();
        Tlv8::new()
            .push(1, &rec)
            .push(2, &video)
            .push(3, &audio)
            .encode()
    }

    #[test]
    fn selected_config_parses() {
        let s = Selected::parse(&selected_tlv()).unwrap();
        assert_eq!(
            s,
            Selected {
                prebuffer_ms: 8000,
                fragment_ms: 4000,
                width: 1280,
                height: 720,
                fps: 30,
                profile: 1,
                level: 1,
                video_kbps: 1500,
                iframe_ms: 4000,
                audio_hz: 24_000,
                audio_kbps: 24,
            }
        );
        assert!(Selected::parse(&[]).is_err());
    }

    #[test]
    fn ffmpeg_args_follow_selection() {
        let sel = Selected::parse(&selected_tlv()).unwrap();
        let j = |a: Vec<String>| a.join(" ");
        let with = j(ffmpeg_args(
            Codec::H265,
            &sel,
            25.0,
            Some(Path::new("/x/a.fifo")),
        ));
        assert!(
            with.contains("-framerate 25.000 -f hevc -i pipe:0"),
            "{with}"
        );
        assert!(
            with.contains("-f alaw -ar 8000 -ac 1 -i /x/a.fifo"),
            "{with}"
        );
        assert!(with.contains("scale=1280:720"), "{with}");
        assert!(with.contains("-bf 0 -r 30"), "{with}");
        assert!(with.contains("-profile:v main -level 3.2"), "{with}");
        assert!(
            with.contains("-c:a aac -profile:a aac_low -ac 1 -ar 24000 -b:a 24k"),
            "{with}"
        );
        assert!(
            with.contains("-movflags frag_keyframe+empty_moov+default_base_moof"),
            "{with}"
        );
        assert!(with.contains("n_forced*4"), "{with}");
        assert!(with.ends_with("-f mp4 pipe:1"), "{with}");
        let without = j(ffmpeg_args(Codec::H265, &sel, 25.0, None));
        assert!(
            !without.contains("alaw") && !without.contains("-c:a"),
            "{without}"
        );
    }

    fn boxed(ty: &[u8; 4], payload: &[u8]) -> Vec<u8> {
        let mut v = (8 + payload.len() as u32).to_be_bytes().to_vec();
        v.extend_from_slice(ty);
        v.extend_from_slice(payload);
        v
    }

    fn sample_mp4(frags: usize) -> Vec<u8> {
        let mut v = [boxed(b"ftyp", b"isom0000"), boxed(b"moov", &[7; 40])].concat();
        for i in 0..frags {
            v.extend(boxed(b"moof", &[i as u8; 24]));
            v.extend(boxed(b"mdat", &vec![i as u8; 300 + i]));
        }
        v
    }

    #[test]
    fn splitter_separates_init_and_fragments_in_any_chunking() {
        let mp4 = sample_mp4(3);
        let expect = |segs: &[Segment]| {
            assert_eq!(segs.len(), 4);
            let Segment::Init(i) = &segs[0] else { panic!() };
            assert_eq!(
                i,
                &[boxed(b"ftyp", b"isom0000"), boxed(b"moov", &[7; 40])].concat()
            );
            for (k, s) in segs[1..].iter().enumerate() {
                let Segment::Fragment(f) = s else { panic!() };
                let want = [
                    boxed(b"moof", &[k as u8; 24]),
                    boxed(b"mdat", &vec![k as u8; 300 + k]),
                ]
                .concat();
                assert_eq!(f, &want);
            }
        };
        for chunk in [1usize, 7, 64, 100_000] {
            let mut sp = Mp4Splitter::default();
            let segs: Vec<Segment> = mp4.chunks(chunk).flat_map(|c| sp.push(c)).collect();
            expect(&segs);
        }
    }

    // Real: ffmpeg generates fMP4 from a synthetic source and the splitter divides it without losing bytes.
    #[tokio::test]
    #[ignore = "requiere ffmpeg"]
    async fn splitter_on_real_ffmpeg_output() {
        let out = std::process::Command::new("ffmpeg")
            .args([
                "-hide_banner",
                "-loglevel",
                "error",
                "-f",
                "lavfi",
                "-i",
                "testsrc=size=320x240:rate=25:duration=9",
            ])
            .args([
                "-c:v",
                "libx264",
                "-g",
                "50",
                "-movflags",
                "frag_keyframe+empty_moov+default_base_moof",
                "-f",
                "mp4",
                "pipe:1",
            ])
            .output()
            .unwrap();
        assert!(out.status.success());
        let mut sp = Mp4Splitter::default();
        let segs: Vec<Segment> = out.stdout.chunks(4096).flat_map(|c| sp.push(c)).collect();
        let Segment::Init(init) = &segs[0] else {
            panic!("no init")
        };
        let ts = inspect::init_timescales(init);
        assert_eq!(ts.len(), 1);
        assert!(inspect::describe_init(init).contains("avc1 320x240"));
        let Segment::Fragment(f0) = &segs[1] else {
            panic!()
        };
        let d = inspect::describe_fragment(f0, &ts);
        assert!(
            d.contains("bmdt=0") && d.contains("primera_sync=true"),
            "{d}"
        );
        let frags = segs
            .iter()
            .filter(|s| matches!(s, Segment::Fragment(_)))
            .count();
        assert!(frags >= 4, "fragmentos: {frags}");
        let total: usize = segs
            .iter()
            .map(|s| match s {
                Segment::Init(b) | Segment::Fragment(b) => b.len(),
            })
            .sum();
        // Only the trailing `mfra` is discarded (random-access index, useless in streaming).
        let mfra = out.stdout.windows(4).rposition(|w| w == b"mfra").unwrap() - 4;
        assert_eq!(total, mfra, "splitter must not lose bytes");
    }

    fn frame(i: i64, gop: i64) -> Frame {
        Frame {
            pts90k: i * 9_000, // 10 fps
            keyframe: i % gop == 0,
            annexb: bytes::Bytes::from_static(b"\0\0\0\x01x"),
        }
    }

    fn info() -> StreamInfo {
        StreamInfo {
            width: 2560,
            height: 1440,
            fps: 10.0,
            has_audio_alaw: false,
        }
    }

    fn classic_acc() -> Arc<RwLock<Accessory>> {
        Arc::new(RwLock::new(build_classic_accessory(
            "cam",
            "AA:BB:CC:DD:EE:FF",
            MaxResolution::P720,
        )))
    }

    #[test]
    fn backlog_starts_at_keyframe_covering_prebuffer() {
        let main = Stream::detached_secs(8);
        for i in 0..100 {
            main.push_frame(frame(i, 20)); // 10 s, 2 s GOP
        }
        let rec = Recorder::new(main, watch::channel(false).1, classic_acc());
        let (b, _rx) = rec.backlog(&Selected::default());
        let open = 99 * 9_000;
        let gop = 2 * 90_000;
        assert!(b[0].keyframe);
        assert!(
            b[0].pts90k <= open - (8 * 90_000 - gop),
            "first pts {}",
            b[0].pts90k
        );
        assert_eq!(b.last().unwrap().pts90k, open);
    }

    #[test]
    fn classic_accessory_has_recording_services_appended_and_linked() {
        let a = build_classic_accessory("cam", "AA:BB:CC:DD:EE:FF", MaxResolution::P720);
        let ty = |t| a.services.iter().find(|s| s.ty == t).unwrap();
        let (rm, dsm, motion) = (
            ty(u::CAMERA_EVENT_RECORDING_MANAGEMENT),
            ty(u::DATA_STREAM_TRANSPORT_MANAGEMENT),
            ty(u::MOTION_SENSOR),
        );
        assert!(rm.iid > dsm.iid && ty(u::CAMERA_OPERATING_MODE).iid > rm.iid);
        assert_eq!(rm.linked, vec![dsm.iid, motion.iid]);
        for c in [
            u::ACTIVE,
            u::SUPPORTED_CAMERA_RECORDING_CONFIG,
            u::SUPPORTED_VIDEO_RECORDING_CONFIG,
            u::SUPPORTED_AUDIO_RECORDING_CONFIG,
            u::SELECTED_CAMERA_RECORDING_CONFIG,
            u::RECORDING_AUDIO_ACTIVE,
        ] {
            assert!(rm.chars.iter().any(|x| x.ty == c), "{c}");
        }
        for c in [
            u::EVENT_SNAPSHOTS_ACTIVE,
            u::HOMEKIT_CAMERA_ACTIVE,
            u::PERIODIC_SNAPSHOTS_ACTIVE,
        ] {
            assert!(
                ty(u::CAMERA_OPERATING_MODE).chars.iter().any(|x| x.ty == c),
                "{c}"
            );
        }
    }

    /// Fake ffmpeg: emits `mp4`, waits for EOF on stdin (end of recording), then emits `tail`
    /// (the final partial fragment).
    fn fake_ffmpeg(mp4: &[u8], tail: &[u8]) -> (tempfile::TempDir, String) {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("out.mp4"), mp4).unwrap();
        std::fs::write(d.path().join("tail.mp4"), tail).unwrap();
        let p = d.path().join("ffmpeg");
        let script = format!(
            "#!/bin/sh\ncat '{}'\ncat >/dev/null\ncat '{}'\n",
            d.path().join("out.mp4").display(),
            d.path().join("tail.mp4").display()
        );
        std::fs::write(&p, script).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        let s = p.to_string_lossy().into_owned();
        (d, s)
    }

    /// Simulated hub: (accessory connection, controller connection).
    async fn peers() -> (HdsConn<DuplexStream>, HdsConn<DuplexStream>) {
        let (a, b) = duplex(1 << 22);
        let acc = HdsKeys::derive(&[7; 32], &[1; 32], &[2; 32]);
        let ctl = HdsKeys {
            encrypt: acc.decrypt,
            decrypt: acc.encrypt,
        };
        (HdsConn::new(a, acc), HdsConn::new(b, ctl))
    }

    async fn send_open(c: &mut HdsConn<DuplexStream>, id: i64, stream: i64) {
        let h = DsValue::dict([
            ("protocol", DsValue::Str("dataSend".into())),
            ("request", DsValue::Str("open".into())),
            ("id", DsValue::Int(id)),
        ]);
        let body = DsValue::dict([
            ("streamId", DsValue::Int(stream)),
            ("type", DsValue::Str(RECORDING_TYPE.into())),
            ("target", DsValue::Str("controller".into())),
            ("reason", DsValue::Str("event".into())),
        ]);
        c.send_raw_for_test(h, body).await;
    }

    /// (dataType, dataSequenceNumber, endOfStream, bytes) of a `dataSend/data`.
    fn data_of(m: &Message) -> (String, i64, bool, usize) {
        let Some(DsValue::Array(p)) = m.body.get("packets") else {
            panic!("no packets")
        };
        let meta = p[0].get("metadata").unwrap();
        let Some(DsValue::Data(d)) = p[0].get("data") else {
            panic!()
        };
        (
            meta.get("dataType")
                .and_then(DsValue::as_str)
                .unwrap()
                .to_string(),
            meta.get("dataSequenceNumber")
                .and_then(DsValue::as_int)
                .unwrap(),
            m.body.get("endOfStream") == Some(&DsValue::Bool(true)),
            d.len(),
        )
    }

    #[tokio::test]
    async fn session_sends_init_then_increasing_fragments_and_eos_at_motion_end() {
        let (_d, bin) = fake_ffmpeg(
            &sample_mp4(2),
            &boxed(b"moof", &[9; 24])
                .into_iter()
                .chain(boxed(b"mdat", &[9; 50]))
                .collect::<Vec<u8>>(),
        );
        let main = Stream::detached_secs(8);
        main.push_frame(frame(0, 20));
        let (mtx, mrx) = watch::channel(true);
        let mut rec = Recorder::new(main.clone(), mrx, classic_acc());
        Arc::get_mut(&mut rec).unwrap().bin = Some(bin);
        Arc::get_mut(&mut rec).unwrap().max_duration = Duration::from_millis(1500);
        let (acc, mut hub) = peers().await;
        let task = tokio::spawn(rec.clone().handle_conn(acc));

        send_open(&mut hub, 77, 5).await;
        let m = hub.next_message().await.unwrap();
        assert!(m.is(Kind::Response, "dataSend", "open"));
        assert_eq!(m.status, Some(0));

        // init + 2 fragments flow without retention while there is motion.
        let mut got = vec![];
        for _ in 0..3 {
            got.push(data_of(&hub.next_message().await.unwrap()));
        }
        assert_eq!(got[0].0, "mediaInitialization");
        assert_eq!(got[0].1, 1);
        assert_eq!((got[1].0.as_str(), got[1].1), ("mediaFragment", 2));
        assert_eq!(got[2].1, 3);
        assert!(got.iter().all(|g| !g.2));

        // A second concurrent open is rejected with BUSY.
        send_open(&mut hub, 78, 6).await;
        let m = hub.next_message().await.unwrap();
        assert_eq!(m.status, Some(6));
        assert_eq!(
            m.body.get("status").and_then(DsValue::as_int),
            Some(reason::BUSY)
        );

        // The end of motion does NOT end the recording (the hub decides): nothing arrives within 400 ms.
        mtx.send(false).unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(400), hub.next_message())
                .await
                .is_err()
        );
        // Duration cap: the last fragment carries endOfStream.
        let last = data_of(&hub.next_message().await.unwrap());
        assert_eq!(
            (last.0.as_str(), last.1, last.2),
            ("mediaFragment", 4, true)
        );
        // The hub closes after endOfStream.
        let h = DsValue::dict([
            ("protocol", DsValue::Str("dataSend".into())),
            ("event", DsValue::Str("close".into())),
        ]);
        hub.send_raw_for_test(h, DsValue::dict([("streamId", DsValue::Int(5))]))
            .await;
        drop(hub);
        task.await.unwrap();
    }

    #[tokio::test]
    async fn session_stops_when_hub_closes_and_frees_the_slot() {
        let (_d, bin) = fake_ffmpeg(&sample_mp4(2), &[]);
        let main = Stream::detached_secs(8);
        main.push_frame(frame(0, 20));
        let mut rec = Recorder::new(main, watch::channel(true).1, classic_acc());
        Arc::get_mut(&mut rec).unwrap().bin = Some(bin);
        let (acc, mut hub) = peers().await;
        let task = tokio::spawn(rec.clone().handle_conn(acc));
        send_open(&mut hub, 1, 9).await;
        assert_eq!(hub.next_message().await.unwrap().status, Some(0));
        assert_eq!(
            data_of(&hub.next_message().await.unwrap()).0,
            "mediaInitialization"
        );
        let h = DsValue::dict([
            ("protocol", DsValue::Str("dataSend".into())),
            ("event", DsValue::Str("close".into())),
        ]);
        hub.send_raw_for_test(h, DsValue::dict([("streamId", DsValue::Int(9))]))
            .await;
        // Another recording can be opened: the previous one released its turn.
        send_open(&mut hub, 2, 10).await;
        let m = loop {
            let m = hub.next_message().await.unwrap();
            if m.is(Kind::Response, "dataSend", "open") {
                break m;
            }
        };
        assert_eq!(m.status, Some(0));
        drop(hub);
        task.await.unwrap();
    }

    #[tokio::test]
    async fn open_rejected_when_camera_inactive() {
        let main = Stream::detached_secs(8);
        let acc_model = classic_acc();
        {
            let mut a = acc_model.write().unwrap();
            let c = a
                .services
                .iter_mut()
                .filter(|s| s.ty == u::CAMERA_OPERATING_MODE)
                .flat_map(|s| &mut s.chars)
                .find(|c| c.ty == u::HOMEKIT_CAMERA_ACTIVE)
                .unwrap();
            c.value = serde_json::json!(0);
        }
        let rec = Recorder::new(main, watch::channel(true).1, acc_model);
        let (acc, mut hub) = peers().await;
        let task = tokio::spawn(rec.handle_conn(acc));
        send_open(&mut hub, 1, 1).await;
        let m = hub.next_message().await.unwrap();
        assert_eq!(
            m.body.get("status").and_then(DsValue::as_int),
            Some(reason::NOT_ALLOWED)
        );
        drop(hub);
        task.await.unwrap();
    }

    fn env(k: &str) -> String {
        std::env::var(k).unwrap_or_else(|_| panic!("missing {k}"))
    }

    /// ~12 s of real motion + prebuffer: validates the fMP4 with ffprobe (h264 + aac, >= 10 s).
    #[tokio::test]
    #[ignore = "requires a real camera (SPIKE_RTSP_MAIN_URL) and ffmpeg/ffprobe"]
    async fn real_camera_records_fmp4() {
        let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();
        let main = Stream::spawn(env("SPIKE_RTSP_MAIN_URL"), 8);
        for _ in 0..300 {
            if main.info().is_some() && main.ring().read().unwrap().last_pts().is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        tokio::time::sleep(Duration::from_secs(9)).await; // fills the prebuffer
        let (_mtx, mrx) = watch::channel(true);
        let acc_model = classic_acc();
        {
            let mut a = acc_model.write().unwrap();
            let c = a
                .services
                .iter_mut()
                .filter(|s| s.ty == u::CAMERA_EVENT_RECORDING_MANAGEMENT)
                .flat_map(|s| &mut s.chars)
                .find(|c| c.ty == u::RECORDING_AUDIO_ACTIVE)
                .unwrap();
            c.value = serde_json::json!(1);
        }
        let rec = Recorder::new(main, mrx, acc_model);

        let (acc, mut hub) = peers().await;
        let task = tokio::spawn(rec.clone().handle_conn(acc));
        send_open(&mut hub, 1, 1).await;
        assert_eq!(hub.next_message().await.unwrap().status, Some(0));
        let t0 = Instant::now();
        let mut mp4 = vec![];
        loop {
            if t0.elapsed() > Duration::from_secs(12) {
                // The hub decides the end: it closes the stream.
                let h = DsValue::dict([
                    ("protocol", DsValue::Str("dataSend".into())),
                    ("event", DsValue::Str("close".into())),
                ]);
                hub.send_raw_for_test(h, DsValue::dict([("streamId", DsValue::Int(1))]))
                    .await;
                break;
            }
            let m = tokio::time::timeout(Duration::from_secs(30), hub.next_message())
                .await
                .expect("no data")
                .unwrap();
            if m.is(Kind::Event, "dataSend", "close") {
                break;
            }
            let Some(DsValue::Array(p)) = m.body.get("packets") else {
                continue;
            };
            if let Some(DsValue::Data(d)) = p[0].get("data") {
                mp4.extend_from_slice(d);
            }
            if m.body.get("endOfStream") == Some(&DsValue::Bool(true)) {
                break;
            }
        }
        let out =
            std::env::var("REC_OUT").unwrap_or_else(|_| "/tmp/hksv-rtsp-bridge-rec.mp4".into());
        std::fs::write(&out, &mp4).unwrap();
        println!("fMP4: {} bytes in {:?}", mp4.len(), t0.elapsed());
        drop(hub);
        let _ = task.await;
        let probe = std::process::Command::new("ffprobe")
            .args([
                "-v",
                "error",
                "-show_entries",
                "stream=codec_name,codec_type:format=duration",
                "-of",
                "default=nw=1",
            ])
            .arg(&out)
            .output()
            .unwrap();
        let txt = String::from_utf8_lossy(&probe.stdout).to_string();
        println!("{txt}");
        assert!(
            txt.contains("codec_name=h264") && txt.contains("codec_name=aac"),
            "{txt}"
        );
        let dur: f64 = txt
            .lines()
            .find_map(|l| l.strip_prefix("duration="))
            .unwrap()
            .parse()
            .unwrap();
        assert!(dur >= 10.0, "duration {dur}");
    }
}
