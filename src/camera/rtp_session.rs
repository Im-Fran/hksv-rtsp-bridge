//! Live-view RTP sessions: one video ffmpeg per session (Annex B via stdin) and, if there is
//! audio, a second audio-only ffmpeg (A-law via stdin -> Opus), both over SRTP toward the
//! controller. Separate processes: with just one, the transcode of each keyframe (every ~3 s)
//! blocked the ffmpeg loop and the audio cut out for ~1 s.
//!
//! SSRC: the ones the accessory announced in Setup Endpoints are used, not the ones from the Start command
//! (iOS filters by the announced ones; see camera-multitier-rtp.ts in Scrypted and hksv3.py).

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, UdpSocket as StdUdp};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use tokio::net::UdpSocket;
use tokio::sync::broadcast::error::RecvError;
use tokio::task::JoinHandle;
use tokio::time::Instant;

use super::legacy::{SelectedConfig, legacy_ffmpeg_args};
use super::setup_endpoints::{EndpointRequest, build_response};
use super::tiers::{Tier, TierSource};
use crate::config::HwAccel;
use crate::hap::server::ConnAddrs;
use crate::hap::tlv8::Tlv8;
use crate::media::ffmpeg::Ffmpeg;
use crate::media::ingest::Stream;
use crate::media::{AudioPacket, Codec, Frame};

const RTCP_TIMEOUT: Duration = Duration::from_secs(30);
/// Setup Endpoints without Start is discarded after this time.
const PENDING_TTL: Duration = Duration::from_secs(60);
/// The guide requires >= 5 simultaneous sessions.
const MAX_SESSIONS: usize = 8;
const VIDEO_PT: u8 = 99;
const AUDIO_PT: u8 = 110;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Status {
    Success = 0,
    UnknownSession = 1,
    NoSuchStream = 2,
    Busy = 3,
    Error = 4,
}

/// Write to RTP Streaming Control (8045).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StartCommand {
    pub session_id: [u8; 16],
    /// 1 = End, 2 = Start.
    pub command: u8,
    pub video_tier: u32,
    pub video_ssrc: u32,
    pub audio_tier: Option<u32>,
    pub audio_ssrc: u32,
}

impl StartCommand {
    pub fn parse(tlv: &[u8]) -> Result<StartCommand> {
        let t = Tlv8::parse(tlv)?;
        Ok(StartCommand {
            session_id: t
                .get(1)
                .and_then(|s| s.try_into().ok())
                .context("missing session id")?,
            command: t.get_u8(2)?.context("missing command")?,
            video_tier: t.get_u32(3)?.unwrap_or(0),
            video_ssrc: t.get_u32(4)?.unwrap_or(0),
            audio_tier: t.get_u32(5)?,
            audio_ssrc: t.get_u32(6)?.unwrap_or(0),
        })
    }
}

/// Response (read afterwards) of RTP Streaming Control.
pub fn status_tlv(session_id: Option<&[u8; 16]>, s: Status) -> Vec<u8> {
    let t = match session_id {
        Some(id) => Tlv8::new().push(1, id),
        None => Tlv8::new(),
    };
    t.push_u8(2, s as u8).encode()
}

/// Output timestamps = arrival time of each frame, at 90 kHz resolution. The camera emits
/// ~12.5 fps even though its pts says 12: with CFR output at 12 fps the video RTP clock ran ~4.4 %
/// slow (52 ms/s) relative to the audio one, and the receiver, which aligns A/V with the RTCP SRs, lost the
/// audio when resyncing every ~3 s. Only applies to the transcode (`copy` already keeps the pts).
pub(super) const VFR: [&str; 4] = ["-fps_mode", "vfr", "-enc_time_base", "1:90000"];

/// Live video input: Annex B (H.264 or HEVC) via stdin.
pub(super) fn input_args(codec: Codec) -> Vec<String> {
    // Live input: wall clocks and short analysis. DO NOT use `-fflags nobuffer`: with an
    // Annex B input over a pipe it discards the first GOP (IDR included) and ffmpeg starts at the P
    // that follow ("Could not find ref with POC N", first image at the next IDR, ~3 s later).
    [
        "-flags",
        "low_delay",
        "-probesize",
        "16384",
        "-analyzeduration",
        "0",
        "-use_wallclock_as_timestamps",
        "1",
        "-f",
        codec.ffmpeg_fmt(),
        "-i",
        "pipe:0",
    ]
    .map(String::from)
    .to_vec()
}

/// Video SRTP output (`-payload_type` ... URL).
pub(super) fn video_out_args(ep: &EndpointRequest, pt: u8, ssrc: u32, pkt: u16) -> Vec<String> {
    srtp_out(&ep.video_srtp, ep, ep.video_port, pt, ssrc, pkt)
}

fn srtp_out(
    p: &super::setup_endpoints::SrtpParams,
    ep: &EndpointRequest,
    port: u16,
    pt: u8,
    ssrc: u32,
    pkt: u16,
) -> Vec<String> {
    let key = B64.encode([&p.key[..], &p.salt[..]].concat());
    let url = format!(
        "srtp://{}:{port}?rtcpport={port}&pkt_size={pkt}",
        host(ep.addr)
    );
    let mut a: Vec<String> = Vec::new();
    let mut add = |xs: &[&str]| a.extend(xs.iter().map(|s| s.to_string()));
    add(&["-payload_type", &pt.to_string(), "-ssrc", &ssrc.to_string()]);
    add(&["-f", "rtp", "-srtp_out_suite", "AES_CM_128_HMAC_SHA1_80"]);
    add(&["-srtp_out_params", &key, &url]);
    a
}

/// Session audio: A-law (8 kHz mono) -> Opus -> SRTP.
#[derive(Clone, Copy, Debug)]
pub(super) struct AudioOut {
    pub pt: u8,
    /// Opus capture rate; the Opus RTP muxer reports 48 kHz.
    pub ar: u32,
    pub kbps: u32,
    pub frame_ms: u32,
}

/// Audio-only ffmpeg: A-law via stdin. The alaw demuxer counts samples (the feed is continuous),
/// with no wall clock: bursty reads would give backwards timestamps and libopus would discard them.
pub(super) fn audio_ffmpeg_args(ep: &EndpointRequest, a: &AudioOut, ssrc: u32) -> Vec<String> {
    let mut v: Vec<String> = [
        "-fflags",
        "nobuffer",
        "-flags",
        "low_delay",
        "-probesize",
        "32",
        "-analyzeduration",
        "0",
        "-f",
        "alaw",
        "-ar",
        "8000",
        "-ac",
        "1",
        "-i",
        "pipe:0",
        "-map",
        "0:a:0",
        "-c:a",
        "libopus",
        "-application",
        "lowdelay",
        "-ar",
        &a.ar.to_string(),
        "-ac",
        "1",
        "-b:a",
        &format!("{}k", a.kbps),
        "-frame_duration",
        &a.frame_ms.to_string(),
    ]
    .map(String::from)
    .to_vec();
    v.extend(srtp_out(&ep.audio_srtp, ep, ep.audio_port, a.pt, ssrc, 400));
    v
}

/// HEVC video ffmpeg (copy or transcode) for Multi-Tier RTP.
pub fn ffmpeg_args(
    tier: &Tier,
    codec: Codec,
    ep: &EndpointRequest,
    video_ssrc: u32,
    hw: HwAccel,
) -> Vec<String> {
    let mut a = input_args(codec);
    let mut add = |xs: &[&str]| a.extend(xs.iter().map(|s| s.to_string()));
    add(&["-map", "0:v:0"]);
    match (tier.source, hw) {
        (TierSource::MainTranscode, HwAccel::None) => {
            add(&VFR);
            add(&[
                "-c:v",
                "libx265",
                "-preset",
                "ultrafast",
                "-tune",
                "zerolatency",
            ]);
            add(&["-vf", "scale=1280:720", "-pix_fmt", "yuv420p"]);
            add(&["-x265-params", "repeat-headers=1:log-level=error"]);
            add(&[
                "-b:v", "768k", "-maxrate", "800k", "-bufsize", "1600k", "-g", "24",
            ]);
        }
        (TierSource::MainTranscode, HwAccel::Vaapi) => {
            add(&VFR);
            add(&["-vaapi_device", "/dev/dri/renderD128"]);
            add(&["-vf", "format=nv12,hwupload,scale_vaapi=w=1280:h=720"]);
            add(&[
                "-c:v",
                "hevc_vaapi",
                "-b:v",
                "768k",
                "-maxrate",
                "800k",
                "-g",
                "24",
            ]);
        }
        _ => add(&["-c:v", "copy", "-bsf:v", "dump_extra"]),
    }
    a.extend(video_out_args(ep, VIDEO_PT, video_ssrc, 1316));
    a
}

fn host(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v) => v.to_string(),
        IpAddr::V6(v) => format!("[{v}]"),
    }
}

/// Local IP of the interface that reaches the controller (a UDP `connect` sends nothing).
fn local_ip_for(peer: IpAddr) -> Result<IpAddr> {
    let bind: SocketAddr = if peer.is_ipv6() {
        "[::]:0".parse()?
    } else {
        "0.0.0.0:0".parse()?
    };
    let s = StdUdp::bind(bind)?;
    s.connect((peer, 9))?;
    Ok(s.local_addr()?.ip())
}

/// "ip video_port audio_port" from the Setup Endpoints response (without keys).
fn log_response(resp: &[u8]) -> Option<String> {
    let t = crate::hap::tlv8::Tlv8::parse(resp).ok()?;
    let a = crate::hap::tlv8::Tlv8::parse(t.get(3)?).ok()?;
    Some(format!(
        "{} video:{} audio:{}",
        std::str::from_utf8(a.get(2)?).ok()?,
        a.get_u16(3).ok()??,
        a.get_u16(4).ok()??
    ))
}

struct Prepared {
    req: EndpointRequest,
    vsock: UdpSocket,
    asock: UdpSocket,
    video_ssrc: u32,
    audio_ssrc: u32,
}

struct Running {
    generation: u64,
    medium: bool,
    task: JoinHandle<()>,
}

struct Entry {
    prep: Arc<Prepared>,
    at: Instant,
    run: Option<Running>,
}

#[derive(Default)]
struct State {
    entries: HashMap<[u8; 16], Entry>,
    next_gen: u64,
}

/// Removes the session from the state when its task finishes (also if it is aborted).
struct Release {
    state: Arc<Mutex<State>>,
    id: [u8; 16],
    generation: u64,
    /// ffmpeg -> controller forwarders (see `relay`).
    relays: Vec<JoinHandle<()>>,
}

impl Drop for Release {
    fn drop(&mut self) {
        for r in &self.relays {
            r.abort();
        }
        let mut st = self.state.lock().unwrap();
        if st
            .entries
            .get(&self.id)
            .and_then(|e| e.run.as_ref())
            .is_some_and(|r| r.generation == self.generation)
        {
            st.entries.remove(&self.id);
        }
    }
}

pub struct Sessions {
    main: Stream,
    sub: Stream,
    tiers: Vec<Tier>,
    hw: HwAccel,
    bin: Option<String>,
    state: Arc<Mutex<State>>,
}

impl Sessions {
    pub fn new(main: Stream, sub: Stream, tiers: Vec<Tier>, hw: HwAccel) -> Sessions {
        Sessions {
            main,
            sub,
            tiers,
            hw,
            bin: None,
            state: Arc::default(),
        }
    }

    #[cfg(test)]
    fn with_bin(mut self, bin: String) -> Sessions {
        self.bin = Some(bin);
        self
    }

    pub fn active(&self) -> usize {
        let st = self.state.lock().unwrap();
        st.entries.values().filter(|e| e.run.is_some()).count()
    }

    /// Setup Endpoints: reserves our own RTCP ports and returns the TLV response.
    ///
    /// `conn`: the HAP connection that wrote the Setup Endpoints. Like HAP-NodeJS/Scrypted
    /// (`sourceAddress`), the announced address is the local one of that connection if it is the same
    /// IP version as the controller's; otherwise, that of the interface that reaches the controller.
    pub fn prepare(&self, req: EndpointRequest, conn: Option<ConnAddrs>) -> Result<Vec<u8>> {
        let local = match conn {
            Some(c) if c.local.is_ipv6() == req.addr.is_ipv6() => c.local.ip(),
            _ => local_ip_for(req.addr)?,
        };
        tracing::info!(
            peer = %conn.map_or("?".into(), |c| c.peer.to_string()),
            conn_local = %conn.map_or("?".into(), |c| c.local.to_string()),
            controller = %req.addr,
            controller_video_port = req.video_port,
            controller_audio_port = req.audio_port,
            "Setup Endpoints: peer HTTP y controlador"
        );
        let resp = self.prepare_with(req, local)?;
        if let Some(r) = log_response(&resp) {
            tracing::info!("Setup Endpoints: response {r}");
        }
        Ok(resp)
    }

    fn prepare_with(&self, mut req: EndpointRequest, local: IpAddr) -> Result<Vec<u8>> {
        let bind = if local.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let sock = || -> Result<UdpSocket> {
            let s = StdUdp::bind(bind)?;
            s.set_nonblocking(true)?;
            Ok(UdpSocket::from_std(s)?)
        };
        let (vsock, asock) = (sock()?, sock()?);
        let (video_ssrc, audio_ssrc) = (rand::random::<u32>(), rand::random::<u32>());
        // The announced ports are ours: that is where the RTCP comes back.
        let ctrl = req.clone();
        req.video_port = vsock.local_addr()?.port();
        req.audio_port = asock.local_addr()?.port();
        let resp = build_response(&req, local, video_ssrc, audio_ssrc);
        let mut st = self.state.lock().unwrap();
        st.entries
            .retain(|_, e| e.run.is_some() || e.at.elapsed() < PENDING_TTL);
        // A previous session with the same id is replaced.
        if let Some(Entry { run: Some(r), .. }) = st.entries.remove(&ctrl.session_id) {
            r.task.abort();
        }
        st.entries.insert(
            ctrl.session_id,
            Entry {
                prep: Arc::new(Prepared {
                    req: ctrl,
                    vsock,
                    asock,
                    video_ssrc,
                    audio_ssrc,
                }),
                at: Instant::now(),
                run: None,
            },
        );
        Ok(resp)
    }

    pub async fn start(&self, c: StartCommand) -> Status {
        let Some(tier) = self.tiers.iter().find(|t| t.id == c.video_tier).cloned() else {
            return Status::Error;
        };
        let from_sub = tier.source == TierSource::SubCopy;
        let medium = tier.source == TierSource::MainTranscode;
        let desc = format!("tier {} ({}x{})", tier.id, tier.width, tier.height);
        self.launch(
            c.session_id,
            from_sub,
            medium,
            c.audio_tier.is_some().then_some(AudioOut {
                pt: AUDIO_PT,
                ar: 16000,
                kbps: 24,
                frame_ms: 20,
            }),
            desc,
            |codec, req, ssrc, hw| ffmpeg_args(&tier, codec, req, ssrc, hw),
        )
        .await
    }

    /// Start of the classic service (117): H.264 transcoded from sub (<= 360p) or main.
    pub async fn start_legacy(&self, sel: SelectedConfig) -> Status {
        let v = &sel.video;
        let desc = format!("H.264 {}x{} {}k", v.width, v.height, v.max_kbps);
        // Only the one decoding the main (1440p) counts as "medium". With CPU (`hwaccel = none`)
        // 1280x720 is scaled from the sub: see `VideoSel::uses_sub`.
        let main = !v.uses_sub() && self.hw == HwAccel::Vaapi;
        let (from_sub, medium) = (!main, main);
        let audio = sel.audio.as_ref().map(|a| AudioOut {
            pt: a.pt,
            ar: a.sample_khz * 1000,
            kbps: u32::from(a.max_kbps).max(8),
            frame_ms: a.frame_ms,
        });
        self.launch(
            sel.session_id,
            from_sub,
            medium,
            audio,
            desc,
            |codec, req, ssrc, hw| legacy_ffmpeg_args(&sel, codec, req, ssrc, hw),
        )
        .await
    }

    async fn launch(
        &self,
        session_id: [u8; 16],
        from_sub: bool,
        medium: bool,
        audio: Option<AudioOut>,
        desc: String,
        build_args: impl FnOnce(Codec, &EndpointRequest, u32, HwAccel) -> Vec<String>,
    ) -> Status {
        let stream = if from_sub { &self.sub } else { &self.main };
        let audio = audio.filter(|_| stream.info().is_some_and(|i| i.has_audio_alaw));
        let mut st = self.state.lock().unwrap();
        if st
            .entries
            .iter()
            .filter(|(id, e)| **id != session_id && e.run.is_some())
            .count()
            >= MAX_SESSIONS
        {
            return Status::Busy;
        }
        if medium
            && st
                .entries
                .iter()
                .any(|(id, e)| *id != session_id && e.run.as_ref().is_some_and(|r| r.medium))
        {
            return Status::Busy;
        }
        st.next_gen += 1;
        let generation = st.next_gen;
        let Some(entry) = st.entries.get_mut(&session_id) else {
            return Status::UnknownSession;
        };
        // Start on an active session = tier change: it is restarted.
        if let Some(r) = entry.run.take() {
            r.task.abort();
        }
        let prep = entry.prep.clone();
        // ffmpeg sends to local sockets and `relay` forwards to the controller FROM the ports
        // announced in Setup Endpoints (see `relay`).
        let (Ok(vl), Ok(al)) = (loopback_sock(), loopback_sock()) else {
            st.entries.remove(&session_id);
            return Status::Error;
        };
        let mut lreq = prep.req.clone();
        lreq.addr = IpAddr::from([127, 0, 0, 1]);
        lreq.video_port = vl.local_addr().map_or(0, |a| a.port());
        lreq.audio_port = al.local_addr().map_or(0, |a| a.port());
        let spawn = |args| match self.bin.as_deref() {
            Some(b) => Ffmpeg::spawn_bin(b, args),
            None => Ffmpeg::spawn(args),
        };
        let ff = match spawn(build_args(stream.codec(), &lreq, prep.video_ssrc, self.hw)) {
            Ok(f) => f,
            Err(e) => {
                tracing::warn!("could not launch ffmpeg: {e:#}");
                st.entries.remove(&session_id);
                return Status::Error;
            }
        };
        // A separate ffmpeg for the audio: see the module header.
        let aud = audio.and_then(
            |a| match spawn(audio_ffmpeg_args(&lreq, &a, prep.audio_ssrc)) {
                Ok(f) => Some((stream.subscribe_audio(), f)),
                Err(e) => {
                    tracing::warn!("no audio, could not launch audio ffmpeg: {e:#}");
                    None
                }
            },
        );
        let (backlog, rx) = stream.subscribe();
        let release = Release {
            state: self.state.clone(),
            id: session_id,
            generation,
            relays: vec![
                tokio::spawn(relay(vl, prep.clone(), false)),
                tokio::spawn(relay(al, prep.clone(), true)),
            ],
        };
        tracing::info!(
            "session {} start: {desc}, audio={}",
            hex::encode(&session_id[..4]),
            aud.is_some()
        );
        let task = tokio::spawn(run(ff, stream.clone(), backlog, rx, aud, prep, release));
        entry.run = Some(Running {
            generation,
            medium,
            task,
        });
        Status::Success
    }

    /// Is there a session running with that id?
    pub fn is_running(&self, id: &[u8; 16]) -> bool {
        let st = self.state.lock().unwrap();
        st.entries.get(id).is_some_and(|e| e.run.is_some())
    }

    pub async fn end(&self, id: [u8; 16]) -> Status {
        let mut st = self.state.lock().unwrap();
        match st.entries.remove(&id) {
            None => Status::UnknownSession,
            Some(Entry { run: None, .. }) => Status::NoSuchStream,
            Some(Entry { run: Some(r), .. }) => {
                r.task.abort(); // kills ffmpeg (kill_on_drop), sockets and FIFO
                Status::Success
            }
        }
    }
}

fn loopback_sock() -> Result<UdpSocket> {
    let s = StdUdp::bind("127.0.0.1:0")?;
    s.set_nonblocking(true)?;
    Ok(UdpSocket::from_std(s)?)
}

/// Separation of audio packets when forwarding them (Opus ptime).
const AUDIO_PACE: Duration = Duration::from_millis(20);
/// A 720p keyframe is ~28 datagrams of 1.4 KB; sending them all at once over Wi-Fi overflows the AP or
/// the iPhone's receive buffer and the IDR is lost (without an IDR there is no image for the whole GOP).
/// Video goes out at most 1 datagram every 2 ms (~5.5 Mbit/s): the IDR takes ~60 ms.
const VIDEO_PACE: Duration = Duration::from_millis(2);
/// Period of our own Sender Reports.
const SR_EVERY: Duration = Duration::from_secs(1);

/// Forwards what ffmpeg writes to the local socket to the controller, sending FROM the
/// socket whose port was announced in Setup Endpoints. An iPhone connected directly over Wi-Fi only
/// accepts RTP/RTCP coming from that address:port (connected UDP sockets; that is why
/// HAP-NodeJS passes `localrtpport` to ffmpeg and go2rtc sends from its own socket); the relay from
/// the HomePod (cellular) does not require it. ffmpeg uses an ephemeral source port, so the video
/// never arrived. Audio is also paced at 20 ms: ffmpeg's alaw demuxer emits it in
/// bursts of 128 ms (6 packets) and iOS's jitter buffer cut it.
async fn relay(local: UdpSocket, prep: Arc<Prepared>, audio: bool) {
    let (sock, port) = if audio {
        (&prep.asock, prep.req.audio_port)
    } else {
        (&prep.vsock, prep.req.video_port)
    };
    let dst = SocketAddr::new(prep.req.addr, port);
    let mut q = std::collections::VecDeque::<Vec<u8>>::new();
    let mut tick = tokio::time::interval(if audio { AUDIO_PACE } else { VIDEO_PACE });
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    let mut primed = false;
    let mut b = [0u8; 2048];
    // Our own SRs with the real send clock (see `srtcp`); ffmpeg's RTCP is discarded.
    let (srtp, hz) = if audio {
        (&prep.req.audio_srtp, 48_000)
    } else {
        (&prep.req.video_srtp, 90_000)
    };
    let (mut sc, mut sender) = (srtcp::Srtcp::new(srtp, hz), srtcp::Sender::default());
    let mut sr_tick = tokio::time::interval(SR_EVERY);
    loop {
        tokio::select! {
            r = local.recv(&mut b) => {
                let Ok(n) = r else { break };
                // ffmpeg's RTCP is discarded; the RTP (audio 20 ms, video 2 ms) is paced.
                if !matches!(b.get(1), Some(200..=204)) {
                    q.push_back(b[..n].to_vec());
                }
            }
            _ = sr_tick.tick() => {
                if let Some(sr) = sc.sender_report(&sender) {
                    let _ = sock.send_to(&sr, dst).await;
                }
            }
            // Starts with ~100 ms of buffer (the demuxer delivers 6 packets every 128 ms).
            _ = tick.tick(), if q.len() > if primed || !audio { 0 } else { 5 } => {
                primed = true;
                // If it builds up (>10 packets = 200 ms) it is drained faster instead of growing.
                let k = if q.len() > if audio { 10 } else { 60 } { 2 } else { 1 };
                for p in q.drain(..k.min(q.len())) {
                    sender.sent(&p);
                    let _ = sock.send_to(&p, dst).await;
                }
            }
        }
    }
}

/// Feeds ffmpeg's stdin through a bounded queue and a separate writer (a slow ffmpeg must not
/// stall the RTCP timeout or `ff.wait()`).
fn spawn_writer(
    mut stdin: tokio::process::ChildStdin,
    cap: usize,
) -> tokio::sync::mpsc::Sender<bytes::Bytes> {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<bytes::Bytes>(cap);
    tokio::spawn(async move {
        use tokio::io::AsyncWriteExt;
        while let Some(b) = rx.recv().await {
            if stdin.write_all(&b).await.is_err() {
                break;
            }
        }
    });
    tx
}

/// Maximum delay the video pacer can add to a frame.
const VIDEO_MAX_DELAY: Duration = Duration::from_millis(250);

/// Like `spawn_writer`, but delivers frames to ffmpeg at an even cadence. The camera emits them in
/// bursts (the IDR arrives ~150-200 ms late and the following ones all at once) and ffmpeg, with
/// `-use_wallclock_as_timestamps`, stamps them with the read time: the video RTP timestamps came out
/// with deltas of 0/2 ms followed by 150+ ms, which iOS's jitter buffer sees as jumps every GOP.
/// Each frame goes out at `previous + average interval (EMA of arrivals)`, bounded between its arrival
/// and arrival + `VIDEO_MAX_DELAY`.
fn spawn_paced_writer(
    mut stdin: tokio::process::ChildStdin,
    cap: usize,
) -> tokio::sync::mpsc::Sender<bytes::Bytes> {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<bytes::Bytes>(cap);
    tokio::spawn(async move {
        use tokio::io::AsyncWriteExt;
        let mut q = std::collections::VecDeque::<(bytes::Bytes, tokio::time::Instant)>::new();
        let (mut last, mut prev, mut avg) = (
            None::<tokio::time::Instant>,
            None::<tokio::time::Instant>,
            0.08f64,
        );
        loop {
            let due = q.front().map(|x| x.1);
            tokio::select! {
                b = rx.recv() => {
                    let Some(b) = b else { break };
                    let now = tokio::time::Instant::now();
                    if let Some(p) = prev {
                        let dt = (now - p).as_secs_f64().clamp(0.04, 0.25);
                        avg = avg * 0.98 + dt * 0.02;
                    }
                    prev = Some(now);
                    let s = last.map_or(now, |l| {
                        (l + Duration::from_secs_f64(avg)).clamp(now, now + VIDEO_MAX_DELAY)
                    });
                    last = Some(s);
                    q.push_back((b, s));
                }
                _ = async { tokio::time::sleep_until(due.unwrap()).await }, if due.is_some() => {
                    let (b, _) = q.pop_front().unwrap();
                    if stdin.write_all(&b).await.is_err() {
                        break;
                    }
                }
            }
        }
    });
    tx
}

/// After an overload an IDR is awaited; if the stream carries none, a keyframe is accepted.
const IDR_WAIT: Duration = Duration::from_secs(6);

/// Feeds video to ffmpeg always starting at an IDR (keyframes carry VPS/SPS/PPS, see
/// `ParamCache`). If the queue fills up, it discards frames until the next IDR instead of loose
/// frames: a gap in the reference chain gives "Could not find ref with POC".
struct VideoFeed {
    codec: Codec,
    tx: tokio::sync::mpsc::Sender<bytes::Bytes>,
    synced: bool,
    since: Instant,
}

impl VideoFeed {
    fn new(codec: Codec, tx: tokio::sync::mpsc::Sender<bytes::Bytes>) -> VideoFeed {
        VideoFeed {
            codec,
            tx,
            synced: false,
            since: Instant::now(),
        }
    }

    /// Discards until the next IDR (new backlog after `Lagged`).
    fn resync(&mut self) {
        self.synced = false;
        self.since = Instant::now();
    }

    /// `Err` if ffmpeg no longer accepts data.
    fn send(&mut self, f: &Frame) -> Result<(), ()> {
        use tokio::sync::mpsc::error::TrySendError;
        if !self.synced
            && !(self.codec.has_idr(&f.annexb) || (f.keyframe && self.since.elapsed() > IDR_WAIT))
        {
            return Ok(());
        }
        match self.tx.try_send(f.annexb.clone()) {
            Ok(()) => self.synced = true,
            Err(TrySendError::Full(_)) => {
                if self.synced {
                    tracing::warn!("session: ffmpeg cannot keep up, dropping until next IDR");
                }
                self.resync();
            }
            Err(TrySendError::Closed(_)) => return Err(()),
        }
        Ok(())
    }
}

type AudioFeed = (tokio::sync::broadcast::Receiver<AudioPacket>, Ffmpeg);

async fn run(
    mut ff: Ffmpeg,
    stream: Stream,
    backlog: Vec<Frame>,
    mut rx: tokio::sync::broadcast::Receiver<Frame>,
    audio: Option<AudioFeed>,
    prep: Arc<Prepared>,
    _release: Release,
) {
    let (mut arx, mut aff, mut atx) = match audio {
        Some((r, mut f)) => {
            let tx = f.take_stdin().map(|s| spawn_writer(s, 256));
            (Some(r), Some(f), tx)
        }
        None => (None, None, None),
    };
    let Some(stdin) = ff.take_stdin() else {
        return;
    };
    let mut feed = VideoFeed::new(stream.codec(), spawn_paced_writer(stdin, 256));
    for f in &backlog {
        if feed.send(f).is_err() {
            return;
        }
    }
    let mut deadline = Instant::now() + RTCP_TIMEOUT;
    let (mut vb, mut ab) = ([0u8; 1500], [0u8; 1500]);
    loop {
        tokio::select! {
            r = rx.recv() => match r {
                Ok(f) => {
                    if feed.send(&f).is_err() {
                        tracing::info!("session: ffmpeg not accepting video");
                        break;
                    }
                }
                Err(RecvError::Lagged(n)) => {
                    // Resyncs from the last keyframe (and only if it is an IDR).
                    tracing::warn!("session: video lagging ({n} frames), resubscribing");
                    let (b, r) = stream.subscribe();
                    rx = r;
                    feed.resync();
                    for f in &b {
                        if feed.send(f).is_err() {
                            return;
                        }
                    }
                }
                Err(RecvError::Closed) => {
                    tracing::info!("session: camera disconnected, ending");
                    break;
                }
            },
            a = async {
                match arx.as_mut() {
                    Some(r) => r.recv().await,
                    None => std::future::pending().await,
                }
            } => match a {
                Ok(p) => {
                    // Non-blocking: if the audio ffmpeg can't keep up, the packet is discarded.
                    if let Some(tx) = &atx
                        && matches!(
                            tx.try_send(p.alaw),
                            Err(tokio::sync::mpsc::error::TrySendError::Closed(_))
                        )
                    {
                        arx = None;
                    }
                }
                Err(RecvError::Lagged(_)) => {}
                Err(RecvError::Closed) => arx = None,
            },
            // If the audio ffmpeg dies, the session continues with video only.
            _ = async {
                match aff.as_mut() {
                    Some(f) => f.wait().await,
                    None => std::future::pending().await,
                }
            } => {
                tracing::warn!("session: audio ffmpeg exited, continuing without audio");
                (arx, aff, atx) = (None, None, None);
            }
            _ = ff.wait() => {
                tracing::warn!("session: ffmpeg exited");
                break;
            }
            _ = prep.vsock.recv_from(&mut vb) => deadline = Instant::now() + RTCP_TIMEOUT,
            _ = prep.asock.recv_from(&mut ab) => deadline = Instant::now() + RTCP_TIMEOUT,
            _ = tokio::time::sleep_until(deadline) => {
                tracing::info!("session: no receiver RTCP for 30 s, ending");
                break;
            }
        }
    }
}

mod srtcp;

#[cfg(test)]
mod live_repro;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::camera::setup_endpoints::parse_request;
    use crate::camera::tiers::tiers_for;
    use crate::media::StreamInfo;

    const FIXTURE: &[u8] = include_bytes!("../../tests/fixtures/setup_endpoints.tlv");

    fn info(w: u16, h: u16) -> StreamInfo {
        StreamInfo {
            width: w,
            height: h,
            fps: 12.0,
            has_audio_alaw: true,
        }
    }

    fn tier(id: u32) -> Tier {
        tiers_for(&info(2560, 1440), &info(640, 360))
            .into_iter()
            .find(|t| t.id == id)
            .unwrap()
    }

    fn joined(t: u32) -> String {
        let ep = parse_request(FIXTURE).unwrap();
        ffmpeg_args(&tier(t), Codec::H265, &ep, 1, HwAccel::None).join(" ")
    }

    #[test]
    fn ffmpeg_args_copy_high() {
        let a = joined(1);
        assert!(a.contains("-c:v copy"));
        assert!(a.contains("-payload_type 99"));
        assert!(a.contains("AES_CM_128_HMAC_SHA1_80"));
        assert!(a.contains("srtp://192.168.50.18:56941?rtcpport=56941&pkt_size=1316"));
        assert!(!a.contains("libx265"));
    }

    #[test]
    fn ffmpeg_args_medium_transcode() {
        let a = joined(2);
        assert!(a.contains("libx265") && a.contains("scale=1280:720") && a.contains("800k"));
        assert!(a.contains("-fps_mode vfr -enc_time_base 1:90000") && !a.contains("nobuffer"));
        assert!(!a.contains("-c:v copy"));
    }

    #[test]
    fn ffmpeg_args_audio_input_and_opus() {
        let ep = parse_request(FIXTURE).unwrap();
        let a = joined(1);
        assert!(!a.contains("alaw") && !a.contains("libopus"));
        let a = audio_ffmpeg_args(&ep, &hsv3_audio(), 2).join(" ");
        assert!(a.contains("-f alaw -ar 8000 -ac 1 -i pipe:0"));
        assert!(a.contains("libopus") && a.contains("-payload_type 110"));
    }

    fn hsv3_audio() -> AudioOut {
        AudioOut {
            pt: AUDIO_PT,
            ar: 16000,
            kbps: 24,
            frame_ms: 20,
        }
    }

    fn rtp_frame(idr: bool, key: bool) -> Frame {
        // NAL IDR_W_RADL (19) o TRAIL_R (1)
        let nal = if idr { 0x26 } else { 0x02 };
        Frame {
            pts90k: 0,
            keyframe: key,
            annexb: bytes::Bytes::from(vec![0, 0, 0, 1, nal, 1, 0xAA]),
        }
    }

    #[tokio::test]
    async fn video_feed_starts_at_idr_and_drops_to_next_idr_on_overflow() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(2);
        let mut f = VideoFeed::new(Codec::H265, tx);
        let (idr, p) = (rtp_frame(true, true), rtp_frame(false, false));
        // Nothing is sent before the first IDR.
        f.send(&p).unwrap();
        f.send(&p).unwrap();
        assert!(rx.try_recv().is_err());
        f.send(&idr).unwrap(); // 1
        f.send(&p).unwrap(); // 2 (queue full)
        f.send(&p).unwrap(); // overflows: loses sync
        assert!(!f.synced);
        rx.recv().await.unwrap();
        rx.recv().await.unwrap();
        // After the overflow, P frames are discarded until the next IDR, even if there is room.
        f.send(&p).unwrap();
        assert!(rx.try_recv().is_err());
        f.send(&idr).unwrap();
        assert_eq!(rx.recv().await.unwrap(), idr.annexb);
        // A non-IDR keyframe is only accepted after IDR_WAIT.
        f.resync();
        f.send(&rtp_frame(false, true)).unwrap();
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn has_idr_detects_nal_types() {
        assert!(Codec::H265.has_idr(&rtp_frame(true, true).annexb));
        assert!(!Codec::H265.has_idr(&rtp_frame(false, false).annexb));
        assert!(Codec::H265.has_idr(&[0, 0, 0, 1, 0x40, 1, 0, 0, 1, 0x28, 1])); // VPS + IDR_N_LP
    }

    /// Fake ffmpeg: consumes stdin and does nothing else.
    fn fake_ffmpeg() -> (tempfile::TempDir, String) {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("ffmpeg");
        std::fs::write(&p, "#!/bin/sh\nexec cat >/dev/null\n").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        let s = p.to_string_lossy().into_owned();
        (d, s)
    }

    fn setup() -> (Sessions, Stream, tempfile::TempDir) {
        let (d, bin) = fake_ffmpeg();
        let main = Stream::detached();
        let s = Sessions::new(
            main.clone(),
            Stream::detached(),
            tiers_for(&info(2560, 1440), &info(640, 360)),
            HwAccel::None,
        )
        .with_bin(bin);
        (s, main, d)
    }

    #[tokio::test]
    async fn prepare_advertises_connection_local_address() {
        let (s, _m, _d) = setup();
        let conn = ConnAddrs {
            peer: "192.168.50.200:50000".parse().unwrap(),
            local: "192.168.50.109:51830".parse().unwrap(),
        };
        let resp = s
            .prepare(parse_request(FIXTURE).unwrap(), Some(conn))
            .unwrap();
        assert!(
            log_response(&resp)
                .unwrap()
                .starts_with("192.168.50.109 video:")
        );
    }

    fn prep(s: &Sessions, n: u8) -> [u8; 16] {
        let mut r = parse_request(FIXTURE).unwrap();
        r.session_id = [n; 16];
        r.addr = "127.0.0.1".parse().unwrap();
        s.prepare_with(r, "127.0.0.1".parse().unwrap()).unwrap();
        [n; 16]
    }

    fn cmd(id: [u8; 16], tier: u32) -> StartCommand {
        StartCommand {
            session_id: id,
            command: 2,
            video_tier: tier,
            video_ssrc: 1,
            audio_tier: None,
            audio_ssrc: 2,
        }
    }

    #[tokio::test]
    async fn second_medium_is_busy() {
        let (s, _m, _d) = setup();
        let (a, b, c) = (prep(&s, 1), prep(&s, 2), prep(&s, 3));
        assert_eq!(s.start(cmd(a, 2)).await, Status::Success);
        assert_eq!(s.start(cmd(b, 2)).await, Status::Busy);
        // High and Low do not count toward the quota
        assert_eq!(s.start(cmd(c, 1)).await, Status::Success);
        assert_eq!(s.active(), 2);
        assert_eq!(s.end(a).await, Status::Success);
        assert_eq!(s.start(cmd(b, 2)).await, Status::Success);
    }

    /// The relay sends from the announced port and paces audio at ~20 ms (burst of 8 -> 8
    /// packets spaced out); RTCP goes out without waiting.
    #[tokio::test]
    async fn relay_sends_from_advertised_port_and_paces_audio() {
        let sink = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut req = parse_request(FIXTURE).unwrap();
        req.addr = "127.0.0.1".parse().unwrap();
        req.video_port = sink.local_addr().unwrap().port();
        req.audio_port = req.video_port;
        let prep = Arc::new(Prepared {
            req,
            vsock: loopback_sock().unwrap(),
            asock: loopback_sock().unwrap(),
            video_ssrc: 1,
            audio_ssrc: 2,
        });
        let (local, feed) = (loopback_sock().unwrap(), loopback_sock().unwrap());
        feed.connect(local.local_addr().unwrap()).await.unwrap();
        let task = tokio::spawn(relay(local, prep.clone(), true));
        feed.send(&[0x80, 200, 0, 0]).await.unwrap(); // ffmpeg's RTCP: discarded
        for i in 0..8u8 {
            let mut pk = [0u8; 24];
            pk[..4].copy_from_slice(&[0x80, 0xee, 0, i]);
            feed.send(&pk).await.unwrap();
        }
        let (mut buf, mut t, mut sr) = ([0u8; 64], vec![], 0);
        for _ in 0..9 {
            let (n, src) = tokio::time::timeout(Duration::from_secs(2), sink.recv_from(&mut buf))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(src.port(), prep.asock.local_addr().unwrap().port());
            if buf[1] == 200 {
                sr += 1; // our own SR (encrypted: header in clear, PT 200) right after the 1st packet
                assert_eq!(n, 58);
            } else {
                t.push(Instant::now());
            }
        }
        assert_eq!(sr, 1);
        // 8 RTP packets: from the 6th to the 8th they already go one per 20 ms.
        assert!(
            t[7] - t[2] >= Duration::from_millis(60),
            "{:?}",
            t[7] - t[2]
        );
        task.abort();
    }

    #[tokio::test]
    async fn end_statuses() {
        let (s, _m, _d) = setup();
        assert_eq!(s.end([9; 16]).await, Status::UnknownSession);
        let a = prep(&s, 1);
        assert_eq!(s.start(cmd([7; 16], 1)).await, Status::UnknownSession);
        assert_eq!(s.start(cmd(a, 99)).await, Status::Error);
        assert_eq!(s.end(a).await, Status::NoSuchStream);
    }

    #[tokio::test(start_paused = true)]
    async fn session_expires_without_rtcp() {
        let (s, _m, _d) = setup();
        let a = prep(&s, 1);
        let b = prep(&s, 2);
        assert_eq!(s.start(cmd(a, 2)).await, Status::Success);
        tokio::time::sleep(Duration::from_secs(20)).await;
        assert_eq!(s.active(), 1);
        tokio::time::sleep(Duration::from_secs(11)).await;
        assert_eq!(s.active(), 0);
        // quota released
        assert_eq!(s.start(cmd(b, 2)).await, Status::Success);
    }

    #[tokio::test(start_paused = true)]
    async fn rtcp_keeps_session_alive() {
        let (s, _m, _d) = setup();
        let a = prep(&s, 1);
        let port = s.state.lock().unwrap().entries[&a]
            .prep
            .vsock
            .local_addr()
            .unwrap()
            .port();
        assert_eq!(s.start(cmd(a, 1)).await, Status::Success);
        let tx = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        for _ in 0..4 {
            tokio::time::sleep(Duration::from_secs(20)).await;
            tx.send_to(b"\x80\xc9\0\x01", ("127.0.0.1", port))
                .await
                .unwrap();
        }
        assert_eq!(s.active(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn camera_disconnect_ends_sessions() {
        let (s, m, _d) = setup();
        let a = prep(&s, 1);
        assert_eq!(s.start(cmd(a, 1)).await, Status::Success);
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert_eq!(s.active(), 1);
        m.disconnect();
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert_eq!(s.active(), 0);
    }

    fn loopback_ep(vport: u16, aport: u16) -> EndpointRequest {
        let mut ep = parse_request(FIXTURE).unwrap();
        ep.addr = "127.0.0.1".parse().unwrap();
        ep.video_port = vport;
        ep.audio_port = aport;
        ep.video_srtp = crate::camera::setup_endpoints::SrtpParams {
            key: [7; 16],
            salt: [9; 14],
        };
        ep.audio_srtp = ep.video_srtp.clone();
        ep
    }

    /// Arrival instants (ms since `t0`) of RTP packets with that payload type.
    fn rtp_arrivals(sock: UdpSocket, pt: u8, t0: Instant, secs: u64) -> JoinHandle<Vec<u128>> {
        tokio::spawn(async move {
            let (mut v, mut buf) = (vec![], [0u8; 2000]);
            let end = t0 + Duration::from_secs(secs);
            while let Ok(Ok(len)) = tokio::time::timeout_at(end, sock.recv(&mut buf)).await {
                if len > 12 && buf[0] >> 6 == 2 && buf[1] & 0x7f == pt {
                    v.push(t0.elapsed().as_millis());
                }
            }
            v
        })
    }

    /// Feeds `secs` s of A-law (20 ms per packet) to the audio ffmpeg, in real time.
    async fn feed_audio(aff: &mut Ffmpeg, secs: u64) {
        let mut tick = tokio::time::interval(Duration::from_millis(20));
        for i in 0..secs * 50 {
            tick.tick().await;
            let pkt: Vec<u8> = (0..160).map(|j| ((i * 7 + j * 13) % 251) as u8).collect();
            aff.write(&pkt).await.unwrap();
        }
    }

    /// Real ffmpeg: HEVC copy video and Opus audio (separate processes) arrive over UDP.
    #[tokio::test]
    #[ignore = "requires ffmpeg"]
    async fn ffmpeg_sends_srtp_over_udp() {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
        let vsock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let asock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ep = loopback_ep(
            vsock.local_addr().unwrap().port(),
            asock.local_addr().unwrap().port(),
        );
        let mut ff = Ffmpeg::spawn(ffmpeg_args(
            &tier(1),
            Codec::H265,
            &ep,
            0x1111,
            HwAccel::None,
        ))
        .unwrap();
        let mut aff = Ffmpeg::spawn(audio_ffmpeg_args(&ep, &hsv3_audio(), 0x2222)).unwrap();
        let kf = std::fs::read("tests/fixtures/keyframe_360p.hevc").unwrap();
        let t0 = Instant::now();
        let (v, a) = (
            rtp_arrivals(vsock, VIDEO_PT, t0, 6),
            rtp_arrivals(asock, AUDIO_PT, t0, 6),
        );
        for _ in 0..30 {
            ff.write(&kf).await.unwrap();
            tokio::time::sleep(Duration::from_millis(83)).await;
        }
        feed_audio(&mut aff, 2).await;
        let (v, a) = (v.await.unwrap().len(), a.await.unwrap().len());
        eprintln!("RTP packets received: video(PT99)={v} audio(PT110)={a}");
        assert!(v > 0, "no video packets");
        assert!(a > 0, "no audio packets");
    }

    /// Regression test for the audio cut every 3-4 s: with the video transcoding keyframes in another
    /// process, the Opus audio must not have gaps > 200 ms in 15 s.
    #[tokio::test]
    #[ignore = "requires ffmpeg (15 s)"]
    async fn audio_rtp_has_no_gaps_while_video_transcodes() {
        let vsock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let asock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let ep = loopback_ep(
            vsock.local_addr().unwrap().port(),
            asock.local_addr().unwrap().port(),
        );
        let sel = legacy_sel([1; 16], 1280, 720); // scales 360p -> 720p: real x264 load
        let mut ff = Ffmpeg::spawn(legacy_ffmpeg_args(
            &sel,
            Codec::H265,
            &ep,
            0x1111,
            HwAccel::None,
        ))
        .unwrap();
        let mut aff = Ffmpeg::spawn(audio_ffmpeg_args(&ep, &hsv3_audio(), 0x2222)).unwrap();
        let kf = std::fs::read("tests/fixtures/keyframe_360p.hevc").unwrap();
        let t0 = Instant::now();
        let a = rtp_arrivals(asock, AUDIO_PT, t0, 16);
        let _v = rtp_arrivals(vsock, VIDEO_PT, t0, 16);
        let video = tokio::spawn(async move {
            // One keyframe (IDR) every ~83 ms: worst case for decode+encode load.
            for _ in 0..180 {
                if ff.write(&kf).await.is_err() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(83)).await;
            }
            ff
        });
        feed_audio(&mut aff, 15).await;
        let arrivals = a.await.unwrap();
        let _ = video.await;
        // The startup is ignored (first 1.5 s: ffmpeg opens the codec).
        let steady: Vec<_> = arrivals.into_iter().filter(|t| *t > 1500).collect();
        let max_gap = steady
            .windows(2)
            .map(|w| w[1] - w[0])
            .max()
            .unwrap_or(u128::MAX);
        eprintln!("audio packets: {} ; max gap: {max_gap} ms", steady.len());
        assert!(steady.len() > 400, "too little audio: {}", steady.len());
        assert!(max_gap <= 200, "audio gap of {max_gap} ms");
    }

    fn legacy_sel(id: [u8; 16], w: u16, h: u16) -> SelectedConfig {
        use crate::camera::legacy::{AudioSel, VideoSel};
        SelectedConfig {
            session_id: id,
            video: VideoSel {
                width: w,
                height: h,
                fps: 25,
                profile: 1,
                level: 0,
                pt: 99,
                max_kbps: 299,
                mtu: 1378,
            },
            audio: Some(AudioSel {
                pt: 110,
                max_kbps: 24,
                sample_khz: 16,
                frame_ms: 20,
            }),
        }
    }

    #[tokio::test]
    async fn legacy_start_end_and_shared_medium_quota() {
        let (mut s, _m, _d) = setup();
        s.hw = HwAccel::Vaapi; // 1280x720 only decodes the main with the GPU
        let (a, b, c) = (prep(&s, 1), prep(&s, 2), prep(&s, 3));
        assert_eq!(
            s.start_legacy(legacy_sel([9; 16], 640, 360)).await,
            Status::UnknownSession
        );
        assert_eq!(
            s.start_legacy(legacy_sel(a, 1280, 720)).await,
            Status::Success
        );
        // 1280x720 legacy shares the "medium" quota with the Medium HEVC tier.
        assert_eq!(s.start(cmd(b, 2)).await, Status::Busy);
        assert_eq!(s.start_legacy(legacy_sel(b, 1280, 720)).await, Status::Busy);
        // 640x360 (sub) does not count.
        assert_eq!(
            s.start_legacy(legacy_sel(c, 640, 360)).await,
            Status::Success
        );
        assert_eq!(s.active(), 2);
        assert!(s.is_running(&a) && !s.is_running(&[9; 16]));
        assert_eq!(s.end(a).await, Status::Success);
        assert_eq!(s.active(), 1);
    }

    /// With CPU, 1280x720 comes from the sub (upscale) and does not use the "medium" quota.
    #[tokio::test]
    async fn legacy_720p_without_gpu_uses_sub_and_no_quota() {
        let (s, _m, _d) = setup();
        let (a, b) = (prep(&s, 1), prep(&s, 2));
        assert_eq!(
            s.start_legacy(legacy_sel(a, 1280, 720)).await,
            Status::Success
        );
        assert_eq!(s.start(cmd(b, 2)).await, Status::Success);
    }

    /// H.264 video (libx264) real: the HEVC 360p keyframe comes out as SRTP PT 99 over UDP.
    #[tokio::test]
    #[ignore = "requires ffmpeg"]
    async fn legacy_ffmpeg_sends_h264_srtp_over_udp() {
        let vsock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut ep = parse_request(FIXTURE).unwrap();
        ep.addr = "127.0.0.1".parse().unwrap();
        ep.video_port = vsock.local_addr().unwrap().port();
        ep.video_srtp = crate::camera::setup_endpoints::SrtpParams {
            key: [7; 16],
            salt: [9; 14],
        };
        let sel = legacy_sel([1; 16], 640, 360);
        let args = legacy_ffmpeg_args(&sel, Codec::H265, &ep, 0x1111, HwAccel::None);
        let mut ff = Ffmpeg::spawn(args).unwrap();
        let kf = std::fs::read("tests/fixtures/keyframe_360p.hevc").unwrap();
        let rx = tokio::spawn(async move {
            let (mut n, mut buf) = (0, [0u8; 2000]);
            let end = Instant::now() + Duration::from_secs(8);
            while let Ok(Ok(len)) = tokio::time::timeout_at(end, vsock.recv(&mut buf)).await {
                if len > 12 && buf[0] >> 6 == 2 && buf[1] & 0x7f == 99 {
                    n += 1;
                }
            }
            n
        });
        for _ in 0..40 {
            ff.write(&kf).await.unwrap();
            tokio::time::sleep(Duration::from_millis(83)).await;
        }
        let n = rx.await.unwrap();
        eprintln!("H.264 RTP packets (PT99) received: {n}");
        assert!(n > 0, "no H.264 video packets");
    }

    #[test]
    fn audio_url_keeps_port_containing_1316() {
        let mut ep = parse_request(FIXTURE).unwrap();
        ep.audio_port = 51316;
        let a = audio_ffmpeg_args(&ep, &hsv3_audio(), 2);
        assert!(a.contains(&"srtp://192.168.50.18:51316?rtcpport=51316&pkt_size=400".to_string()));
    }

    #[tokio::test]
    async fn caps_total_sessions_at_eight() {
        let (s, _m, _d) = setup();
        for n in 1..=8 {
            let id = prep(&s, n);
            assert_eq!(s.start(cmd(id, 1)).await, Status::Success);
        }
        let id = prep(&s, 9);
        assert_eq!(s.start(cmd(id, 1)).await, Status::Busy);
        assert_eq!(s.active(), 8);
    }

    #[test]
    fn start_command_parses() {
        let id = [3u8; 16];
        let t = Tlv8::new()
            .push(1, &id)
            .push_u8(2, 2)
            .push_u32(3, 1)
            .push_u32(4, 0xAABBCCDD)
            .push_u32(5, 1)
            .push_u32(6, 7)
            .encode();
        let c = StartCommand::parse(&t).unwrap();
        assert_eq!((c.command, c.video_tier, c.video_ssrc), (2, 1, 0xAABBCCDD));
        assert_eq!((c.audio_tier, c.audio_ssrc), (Some(1), 7));
    }
}
