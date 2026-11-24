//! Remote live view (phone) over WebRTC: service 8033 (Solicit Offer, Provide Answer,
//! Streaming Control, Reoffer, Update Session, Number of Active Sessions).
//!
//! Design: `str0m` in "direct API" mode (ICE + DTLS + SRTP, without its SDP layer), one UDP socket per
//! session, with the SDP hand-written like the working references (cameraui-homekit
//! `webrtcSessions.ts`, Scrypted `camera-webrtc.ts`):
//! - accessory offer with H265 PT 99 (rid/simulcast/b=AS/TIAS of the tier) and Opus PT 110;
//! - ICE candidates inside the SDP (host) and the TLV candidate list left empty;
//! - SFrame always on (the references: without it the remote video does not load);
//! - each H.265 frame (4-byte length prefixes, like VideoToolbox) is encrypted with SFrame and split
//!   with the S/E descriptor (`sframe::packetize`), not RFC 7798: SFrame makes the payload opaque.
//!
//! Video: the sub stream (640x360, Low tier) in passthrough. Audio: A-law -> Opus with one ffmpeg per
//! session (A-law on stdin, RTP output to a loopback socket).

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use str0m::format::{Codec, FormatParams};
use str0m::media::{Frequency, MediaKind, Mid, Pt, Rid};
use str0m::net::{Protocol, Receive};
use str0m::rtp::{Extension, ExtensionValues, RtpWrite, Ssrc};
use str0m::{Candidate, Event, IceConnectionState, Input, Output, Rtc, RtcConfig};
use tokio::net::UdpSocket;
use tokio::sync::{Notify, broadcast};

use super::services::{AUDIO_PT, VIDEO_PT};
use super::sframe::{self, SENDER_KID, SFrameStream, Suite};
use super::tiers::Tier;
use crate::hap::server::ConnAddrs;
use crate::hap::tlv8::Tlv8;
use crate::media::ffmpeg::Ffmpeg;
use crate::media::ingest::Stream;
use crate::media::{AudioPacket, Frame};

/// Maximum simultaneous sessions (the guide requires >= 6).
pub const MAX_SESSIONS: usize = 6;
/// A requested session that gets no response within this time is discarded.
const ANSWER_TIMEOUT: Duration = Duration::from_secs(60);
/// Maximum payload per RTP packet (SFrame descriptor included).
const MAX_PAYLOAD: usize = 1200;
/// Floor for the offered `max-br`: the real sub stream (~260 kbps) exceeds the 190 kbps of the Low tier.
const MIN_MAX_BR_KBPS: u32 = 400;
/// Value of the `rtp-stream-id` header extension in every video packet (a=rid:1 of the offer).
const RID: &str = "1";

/// `HKSV_RTSP_BRIDGE_WEBRTC_RID=0` disables the rid header extension (the references don't send it).
fn send_rid() -> bool {
    std::env::var("HKSV_RTSP_BRIDGE_WEBRTC_RID").map_or(true, |v| v != "0")
}

/// WebRTC Streaming Status states (guide 4.18/4.19).
pub const ST_SUCCESS: u8 = 0;
pub const ST_UNKNOWN: u8 = 1;
pub const ST_BUSY: u8 = 2;
pub const ST_ERROR: u8 = 3;

/// Solicit Offer states.
pub const SO_SUCCESS: u8 = 0;
pub const SO_PRIVACY: u8 = 1;
pub const SO_ERROR: u8 = 2;

pub type Sid = [u8; 16];

/// Offer generated for Solicit Offer.
pub struct Solicited {
    pub sid: Sid,
    pub sdp: String,
    /// The accessory's SFrame group key and its KID.
    pub sframe: Option<(Vec<u8>, u64)>,
}

/// SDP parameters repeated in the response to a Reoffer.
#[derive(Clone)]
struct SdpParams {
    ufrag: String,
    pwd: String,
    fingerprint: String,
    video_ssrc: u32,
    audio_ssrc: u32,
    tier: Tier,
    candidates: Vec<String>,
}

struct Pending {
    rtc: Rtc,
    sock: UdpSocket,
    local: SocketAddr,
    params: SdpParams,
    group_key: Vec<u8>,
    at: Instant,
}

enum Phase {
    Solicited(Box<Pending>),
    Active {
        cancel: Arc<Notify>,
        params: SdpParams,
        dtls_active: bool,
    },
}

#[derive(Default)]
struct State {
    sessions: HashMap<Sid, Phase>,
}

impl State {
    fn active(&self) -> usize {
        self.sessions
            .values()
            .filter(|p| matches!(p, Phase::Active { .. }))
            .count()
    }
}

pub struct WebRtc {
    main: Stream,
    sub: Stream,
    tier: Tier,
    state: Arc<Mutex<State>>,
    /// Called with the active session count whenever it changes.
    on_count: Arc<dyn Fn(u8) + Send + Sync>,
}

impl WebRtc {
    pub fn new(
        main: Stream,
        sub: Stream,
        tier: Tier,
        on_count: Arc<dyn Fn(u8) + Send + Sync>,
    ) -> Arc<WebRtc> {
        Arc::new(WebRtc {
            main,
            sub,
            tier,
            state: Arc::default(),
            on_count,
        })
    }

    pub fn active(&self) -> usize {
        self.state.lock().unwrap().active()
    }

    fn notify_count(&self) {
        (self.on_count)(self.active().min(255) as u8);
    }

    /// Solicit Offer: builds Rtc + socket + SDP offer. `Err(())` -> the caller responds Error.
    pub fn solicit(self: &Arc<Self>, conn: Option<ConnAddrs>) -> Result<Solicited> {
        let sid: Sid = rand::random();
        {
            let st = self.state.lock().unwrap();
            if st.sessions.len() >= MAX_SESSIONS {
                bail!("maximum of {MAX_SESSIONS} WebRTC sessions");
            }
        }
        let ip = conn.map_or(IpAddr::V4(Ipv4Addr::LOCALHOST), |c| c.local.ip());
        let bind = if ip.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" };
        let std_sock = std::net::UdpSocket::bind(bind)?;
        std_sock.set_nonblocking(true)?;
        let sock = UdpSocket::from_std(std_sock)?;
        let local = SocketAddr::new(ip, sock.local_addr()?.port());

        let mut rtc = new_rtc();
        let (creds, fingerprint) = {
            let mut d = rtc.direct_api();
            d.set_ice_controlling(true);
            (
                d.local_ice_credentials(),
                d.local_dtls_fingerprint().to_string(),
            )
        };
        let cand = Candidate::host(local, "udp").context("host candidate")?;
        let cand_sdp = rtc
            .add_local_candidate(cand)
            .map(|c| c.to_sdp_string())
            .context("local candidate rejected")?;
        let (video_ssrc, audio_ssrc) = (rand::random::<u32>(), rand::random::<u32>());
        {
            let mut d = rtc.direct_api();
            let (vm, am): (Mid, Mid) = ("0".into(), "1".into());
            d.declare_media(vm, MediaKind::Video);
            d.declare_media(am, MediaKind::Audio);
            d.declare_stream_tx(
                Ssrc::from(video_ssrc),
                None,
                vm,
                send_rid().then(|| RID.into()),
            )
            .set_unpaced(true);
            d.declare_stream_tx(Ssrc::from(audio_ssrc), None, am, None)
                .set_unpaced(true);
        }
        let params = SdpParams {
            ufrag: creds.ufrag,
            pwd: creds.pass,
            fingerprint,
            video_ssrc,
            audio_ssrc,
            tier: self.tier.clone(),
            candidates: vec![cand_sdp.trim_start_matches("a=").to_string()],
        };
        let mut group_key = vec![0u8; 32];
        for b in &mut group_key {
            *b = rand::random();
        }
        let sdp = build_offer(&params, rand::random::<u32>() as u64);
        let mut st = self.state.lock().unwrap();
        st.sessions.insert(
            sid,
            Phase::Solicited(Box::new(Pending {
                rtc,
                sock,
                local,
                params,
                group_key: group_key.clone(),
                at: Instant::now(),
            })),
        );
        drop(st);
        let me = self.clone();
        tokio::spawn(async move {
            tokio::time::sleep(ANSWER_TIMEOUT).await;
            let mut st = me.state.lock().unwrap();
            if matches!(st.sessions.get(&sid), Some(Phase::Solicited(_))) {
                st.sessions.remove(&sid);
                tracing::warn!("WebRTC {}: no answer in 60 s, dropped", short(&sid));
            }
        });
        Ok(Solicited {
            sid,
            sdp,
            sframe: Some((group_key, SENDER_KID)),
        })
    }

    /// Provide Answer: applies the answer and starts the session.
    pub fn answer(self: &Arc<Self>, sid: Sid, sdp: &str, extra: &[String]) -> u8 {
        let mut st = self.state.lock().unwrap();
        match st.sessions.get(&sid) {
            None => return ST_UNKNOWN,
            Some(Phase::Active { .. }) => return ST_ERROR, // ya respondida
            Some(Phase::Solicited(_)) => {}
        }
        // An invalid or unapplicable answer ends the session.
        let Some(Phase::Solicited(p)) = st.sessions.remove(&sid) else {
            unreachable!()
        };
        tracing::info!("WebRTC {}: answer: {}", short(&sid), sdp_summary(sdp));
        let ans = match parse_answer(sdp, extra) {
            Ok(a) => a,
            Err(e) => {
                tracing::warn!("WebRTC {}: invalid answer: {e:#}", short(&sid));
                return ST_ERROR;
            }
        };
        let Pending {
            mut rtc,
            sock,
            local,
            params,
            group_key,
            ..
        } = *p;
        let dtls_active = ans.setup != "active"; // if the controller is active, we are the server
        let remote_cands = ans.candidates.len();
        if let Err(e) = configure(&mut rtc, &ans, dtls_active) {
            tracing::warn!("WebRTC {}: could not configure: {e:#}", short(&sid));
            return ST_ERROR;
        }
        tracing::info!(
            "WebRTC {}: answer applied ({} remote candidates, dtls {})",
            short(&sid),
            remote_cands,
            if dtls_active { "cliente" } else { "servidor" }
        );
        let cancel = Arc::new(Notify::new());
        st.sessions.insert(
            sid,
            Phase::Active {
                cancel: cancel.clone(),
                params: params.clone(),
                dtls_active,
            },
        );
        drop(st);
        self.notify_count();
        let run = Run {
            sid,
            rtc,
            sock,
            local,
            params,
            group_key,
            video: self.sub.clone(),
            audio: if self.sub.info().is_some_and(|i| i.has_audio_alaw) {
                self.sub.clone()
            } else {
                self.main.clone()
            },
            cancel,
        };
        let me = self.clone();
        tokio::spawn(async move {
            if let Err(e) = run.go().await {
                tracing::warn!("WebRTC {}: ended with error: {e:#}", short(&sid));
            }
            me.finish(&sid);
        });
        ST_SUCCESS
    }

    /// Removes the session and reports the new count.
    fn finish(&self, sid: &Sid) {
        let had = self.state.lock().unwrap().sessions.remove(sid).is_some();
        if had {
            tracing::info!("WebRTC {}: session ended", short(sid));
        }
        self.notify_count();
    }

    /// Streaming Control End.
    pub fn end(&self, sid: &Sid) -> u8 {
        let phase = self.state.lock().unwrap().sessions.remove(sid);
        match phase {
            None => ST_UNKNOWN,
            Some(Phase::Active { cancel, .. }) => {
                cancel.notify_one();
                self.notify_count();
                ST_SUCCESS
            }
            Some(Phase::Solicited(_)) => {
                self.notify_count();
                ST_SUCCESS
            }
        }
    }

    /// Ends all sessions (Streaming Enabled / privacy / shutdown).
    pub fn end_all(&self) {
        let ids: Vec<Sid> = self
            .state
            .lock()
            .unwrap()
            .sessions
            .keys()
            .copied()
            .collect();
        for id in ids {
            self.end(&id);
        }
    }

    /// Reoffer: returns the response SDP (same ICE credentials/fingerprint).
    pub fn reoffer(&self, sid: &Sid, offer: &str) -> Result<String, u8> {
        let st = self.state.lock().unwrap();
        match st.sessions.get(sid) {
            None => Err(ST_UNKNOWN),
            Some(Phase::Solicited(_)) => Err(ST_ERROR),
            Some(Phase::Active {
                params,
                dtls_active,
                ..
            }) => build_reanswer(params, *dtls_active, offer).map_err(|e| {
                tracing::warn!("WebRTC {}: invalid reoffer: {e:#}", short(sid));
                ST_ERROR
            }),
        }
    }

    /// Update Session: we only send media; receive keys are registered and ignored.
    pub fn update(&self, sid: &Sid, added: usize, removed: usize) -> u8 {
        let st = self.state.lock().unwrap();
        match st.sessions.get(sid) {
            Some(Phase::Active { .. }) => {
                tracing::info!(
                    "WebRTC {}: receive keys +{added} -{removed} (no incoming audio, ignored)",
                    short(sid)
                );
                ST_SUCCESS
            }
            Some(_) => ST_ERROR,
            None => ST_UNKNOWN,
        }
    }
}

/// SDP lines without secrets (no ice, fingerprint or candidates), for diagnostics.
fn sdp_summary(sdp: &str) -> String {
    const KEEP: [&str; 14] = [
        "m=",
        "b=",
        "a=mid",
        "a=rtpmap",
        "a=fmtp",
        "a=rtcp-fb",
        "a=rid",
        "a=simulcast",
        "a=extmap",
        "a=sendonly",
        "a=recvonly",
        "a=sendrecv",
        "a=inactive",
        "a=setup",
    ];
    sdp.lines()
        .map(str::trim)
        .filter(|l| KEEP.iter().any(|k| l.starts_with(k)))
        .collect::<Vec<_>>()
        .join(" | ")
}

fn short(sid: &Sid) -> String {
    hex::encode(&sid[..4])
}

fn rtc_config() -> RtcConfig {
    let mut cfg = RtcConfig::new().clear_codecs();
    cfg.codec_config().add_config(
        Pt::new_with_value(VIDEO_PT),
        None,
        Codec::H265,
        Frequency::NINETY_KHZ,
        None,
        FormatParams::default(),
    );
    cfg.codec_config().add_config(
        Pt::new_with_value(AUDIO_PT),
        None,
        Codec::Opus,
        Frequency::FORTY_EIGHT_KHZ,
        Some(2),
        FormatParams::default(),
    );
    cfg = cfg
        .clear_extension_map()
        .set_extension(1, Extension::RtpStreamId);
    cfg.set_stats_interval(Some(Duration::from_secs(5)))
}

fn new_rtc() -> Rtc {
    rtc_config().build(Instant::now())
}

// ---------------------------------------------------------------- SDP

fn build_offer(p: &SdpParams, session_id: u64) -> String {
    let t = &p.tier;
    let mut s = String::new();
    let mut l = |x: &str| {
        s.push_str(x);
        s.push_str("\r\n");
    };
    l("v=0");
    l(&format!("o=- {session_id} 2 IN IP4 127.0.0.1"));
    l("s=-");
    l("t=0 0");
    l("a=group:BUNDLE 0 1");
    l("a=msid-semantic: WMS *");
    let ice = |l: &mut dyn FnMut(&str)| {
        l(&format!("a=ice-ufrag:{}", p.ufrag));
        l(&format!("a=ice-pwd:{}", p.pwd));
        l(&format!("a=fingerprint:{}", p.fingerprint));
        l("a=setup:actpass");
    };
    l(&format!("m=video 9 UDP/TLS/RTP/SAVPF {VIDEO_PT}"));
    l("c=IN IP4 0.0.0.0");
    // Without bandwidth the viewer reports "no valid streams".
    let kbps = t.peak_kbps.max(MIN_MAX_BR_KBPS);
    l(&format!("b=AS:{kbps}"));
    l(&format!("b=TIAS:{}", kbps * 1000));
    l("a=rtcp:9 IN IP4 0.0.0.0");
    ice(&mut l);
    l("a=mid:0");
    l("a=msid:hksv-rtsp-bridge video0");
    l("a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id");
    l("a=sendonly");
    l("a=rtcp-mux");
    l(&format!("a=rtpmap:{VIDEO_PT} H265/90000"));
    l(&format!("a=rtcp-fb:{VIDEO_PT} nack"));
    l(&format!("a=rtcp-fb:{VIDEO_PT} nack pli"));
    l(&format!("a=rtcp-fb:{VIDEO_PT} ccm fir"));
    l(&format!(
        "a=fmtp:{VIDEO_PT} profile-id=1;tier-flag=0;level-id=153;tx-mode=SRST"
    ));
    // iOS 27 rejects a video offer without rid.
    l(&format!(
        "a=rid:1 send max-width={};max-height={};max-fps={};max-br={}",
        t.width,
        t.height,
        t.fps,
        kbps * 1000
    ));
    l("a=simulcast:send 1");
    l(&format!("a=ssrc:{} cname:hksv-rtsp-bridge", p.video_ssrc));
    l(&format!(
        "a=ssrc:{} msid:hksv-rtsp-bridge video0",
        p.video_ssrc
    ));
    for c in &p.candidates {
        l(&format!("a={c}"));
    }
    l("a=end-of-candidates");
    l(&format!("m=audio 9 UDP/TLS/RTP/SAVPF {AUDIO_PT}"));
    l("c=IN IP4 0.0.0.0");
    l("a=rtcp:9 IN IP4 0.0.0.0");
    ice(&mut l);
    l("a=mid:1");
    l("a=msid:hksv-rtsp-bridge audio0");
    l("a=sendonly");
    l("a=rtcp-mux");
    l(&format!("a=rtpmap:{AUDIO_PT} opus/48000/2"));
    l(&format!(
        "a=fmtp:{AUDIO_PT} minptime=20;useinbandfec=1;stereo=0;sprop-stereo=0"
    ));
    l(&format!("a=ssrc:{} cname:hksv-rtsp-bridge", p.audio_ssrc));
    l(&format!(
        "a=ssrc:{} msid:hksv-rtsp-bridge audio0",
        p.audio_ssrc
    ));
    s
}

/// Response to a Reoffer: our sections (mid 0 video, mid 1 audio) and the rest rejected.
fn build_reanswer(p: &SdpParams, dtls_active: bool, offer: &str) -> Result<String> {
    let mut mlines = Vec::new();
    for line in offer.lines().map(str::trim) {
        if let Some(rest) = line.strip_prefix("m=") {
            let mut it = rest.split_whitespace();
            let kind = it.next().unwrap_or("").to_string();
            let pts: Vec<&str> = it.skip(2).collect();
            mlines.push((kind, pts.first().copied().unwrap_or("0").to_string(), None));
        } else if let Some(mid) = line.strip_prefix("a=mid:")
            && let Some(m) = mlines.last_mut()
        {
            m.2 = Some(mid.to_string());
        }
    }
    if mlines.is_empty() {
        bail!("reoffer without m= sections");
    }
    let accepted: Vec<&str> = mlines
        .iter()
        .filter_map(|(_, _, mid)| mid.as_deref())
        .filter(|m| *m == "0" || *m == "1")
        .collect();
    let setup = if dtls_active { "active" } else { "passive" };
    let mut s = String::from("v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n");
    s.push_str(&format!("a=group:BUNDLE {}\r\n", accepted.join(" ")));
    for (kind, pt, mid) in &mlines {
        let mid = mid.clone().unwrap_or_default();
        let ours = (kind == "video" && mid == "0") || (kind == "audio" && mid == "1");
        if !ours {
            s.push_str(&format!(
                "m={kind} 0 UDP/TLS/RTP/SAVPF {pt}\r\nc=IN IP4 0.0.0.0\r\na=mid:{mid}\r\na=inactive\r\n"
            ));
            continue;
        }
        let video = kind == "video";
        let ssrc = if video { p.video_ssrc } else { p.audio_ssrc };
        s.push_str(&format!(
            "m={kind} 9 UDP/TLS/RTP/SAVPF {}\r\nc=IN IP4 0.0.0.0\r\na=rtcp:9 IN IP4 0.0.0.0\r\n\
             a=ice-ufrag:{}\r\na=ice-pwd:{}\r\na=fingerprint:{}\r\na=setup:{setup}\r\na=mid:{mid}\r\n\
             a=sendonly\r\na=rtcp-mux\r\n",
            if video { VIDEO_PT } else { AUDIO_PT },
            p.ufrag,
            p.pwd,
            p.fingerprint
        ));
        if video {
            s.push_str(&format!(
                "a=rtpmap:{VIDEO_PT} H265/90000\r\na=fmtp:{VIDEO_PT} profile-id=1;tier-flag=0;level-id=153;tx-mode=SRST\r\n"
            ));
        } else {
            s.push_str(&format!(
                "a=rtpmap:{AUDIO_PT} opus/48000/2\r\na=fmtp:{AUDIO_PT} minptime=20;useinbandfec=1;stereo=0;sprop-stereo=0\r\n"
            ));
        }
        s.push_str(&format!("a=ssrc:{ssrc} cname:hksv-rtsp-bridge\r\n"));
    }
    Ok(s)
}

struct Answer {
    ufrag: String,
    pwd: String,
    fingerprint: String,
    setup: String,
    candidates: Vec<String>,
}

fn parse_answer(sdp: &str, extra: &[String]) -> Result<Answer> {
    let (mut ufrag, mut pwd, mut fp, mut setup) = (None, None, None, None);
    let mut candidates: Vec<String> = Vec::new();
    for line in sdp.lines().map(str::trim) {
        if let Some(v) = line.strip_prefix("a=ice-ufrag:") {
            ufrag.get_or_insert(v.to_string());
        } else if let Some(v) = line.strip_prefix("a=ice-pwd:") {
            pwd.get_or_insert(v.to_string());
        } else if let Some(v) = line.strip_prefix("a=fingerprint:") {
            fp.get_or_insert(v.to_string());
        } else if let Some(v) = line.strip_prefix("a=setup:") {
            setup.get_or_insert(v.to_string());
        } else if let Some(v) = line.strip_prefix("a=candidate:") {
            candidates.push(format!("candidate:{v}"));
        }
    }
    for c in extra {
        let c = c.trim().trim_start_matches("a=");
        if !c.is_empty() && !candidates.iter().any(|x| x == c) {
            candidates.push(c.to_string());
        }
    }
    Ok(Answer {
        ufrag: ufrag.context("answer without ice-ufrag")?,
        pwd: pwd.context("answer without ice-pwd")?,
        fingerprint: fp.context("answer without fingerprint")?,
        setup: setup.unwrap_or_else(|| "active".into()),
        candidates,
    })
}

fn configure(rtc: &mut Rtc, a: &Answer, dtls_active: bool) -> Result<()> {
    for c in &a.candidates {
        match Candidate::from_sdp_string(c) {
            Ok(c) => rtc.add_remote_candidate(c),
            Err(e) => tracing::debug!("remote candidate ignored: {e}"),
        }
    }
    {
        let mut d = rtc.direct_api();
        d.set_remote_ice_credentials(str0m::IceCreds {
            ufrag: a.ufrag.clone(),
            pass: a.pwd.clone(),
        });
        d.set_remote_fingerprint(
            a.fingerprint
                .parse()
                .map_err(|e| anyhow!("invalid fingerprint: {e:?}"))?,
        );
        d.start_dtls(dtls_active)?;
    }
    rtc.handle_input(Input::Timeout(Instant::now()))?;
    Ok(())
}

// -------------------------------------------------------------- Media

/// Annex B access unit -> NALs with 4-byte length prefix (VideoToolbox format).
pub fn annexb_to_length_prefixed(data: &[u8]) -> Vec<u8> {
    let mut starts = Vec::new(); // (inicio del NAL, inicio del start code)
    let mut i = 0;
    while i + 3 <= data.len() {
        if data[i] == 0 && data[i + 1] == 0 && data[i + 2] == 1 {
            let sc = if i > 0 && data[i - 1] == 0 { i - 1 } else { i };
            starts.push((i + 3, sc));
            i += 3;
        } else {
            i += 1;
        }
    }
    let mut out = Vec::with_capacity(data.len() + 16);
    for (n, &(s, _)) in starts.iter().enumerate() {
        let end = starts.get(n + 1).map_or(data.len(), |&(_, sc)| sc);
        if end > s {
            out.extend_from_slice(&((end - s) as u32).to_be_bytes());
            out.extend_from_slice(&data[s..end]);
        }
    }
    out
}

struct Run {
    sid: Sid,
    rtc: Rtc,
    sock: UdpSocket,
    local: SocketAddr,
    params: SdpParams,
    group_key: Vec<u8>,
    video: Stream,
    audio: Stream,
    cancel: Arc<Notify>,
}

/// Send state of an RTP stream.
struct Tx {
    ssrc: Ssrc,
    pt: Pt,
    seq: u64,
    sframe: SFrameStream,
    rid: Option<Rid>,
}

impl Tx {
    fn send(&mut self, rtc: &mut Rtc, data: &[u8], ts: u32, marker: bool) {
        let sealed = self.sframe.protect(data);
        let now = Instant::now();
        for (payload, m) in sframe::packetize(&sealed, MAX_PAYLOAD, marker) {
            if let Some(s) = rtc.direct_api().stream_tx(&self.ssrc) {
                let ext = ExtensionValues {
                    rid: self.rid,
                    ..Default::default()
                };
                s.write_rtp(
                    RtpWrite::new(self.pt, self.seq.into(), ts, now, payload)
                        .marker(m)
                        .ext_vals(ext),
                );
            }
            self.seq += 1;
        }
    }
}

/// Maps camera pts -> continuous RTP timestamp (the camera resets pts on reconnect).
struct Clock {
    base: u32,
    origin: Option<i64>,
    last: u32,
}

impl Clock {
    fn ts(&mut self, pts: i64) -> u32 {
        let o = *self.origin.get_or_insert(pts);
        let mut ts = self.base.wrapping_add((pts - o) as u32);
        if ts.wrapping_sub(self.last) as i32 <= 0 && self.last != 0 {
            // pts went backwards: rebase to keep going without jumping back
            ts = self.last.wrapping_add(3600);
            self.origin = Some(pts);
            self.base = ts;
        }
        self.last = ts;
        ts
    }
}

impl Run {
    async fn go(mut self) -> Result<()> {
        let sid = self.sid;
        let mut buf = vec![0u8; 2048];
        let mut video_rx: Option<broadcast::Receiver<Frame>> = None;
        let mut audio_rx: Option<broadcast::Receiver<AudioPacket>> = None;
        let mut need_key = true;
        let mut last_key: Option<Instant> = None;
        let mut vtx = Tx {
            ssrc: self.params.video_ssrc.into(),
            pt: Pt::new_with_value(VIDEO_PT),
            seq: rand::random::<u16>() as u64,
            sframe: SFrameStream::new(
                &self.group_key,
                SENDER_KID,
                self.params.video_ssrc,
                Suite::Video,
            ),
            rid: send_rid().then(|| RID.into()),
        };
        let mut atx = Tx {
            ssrc: self.params.audio_ssrc.into(),
            pt: Pt::new_with_value(AUDIO_PT),
            seq: rand::random::<u16>() as u64,
            sframe: SFrameStream::new(
                &self.group_key,
                SENDER_KID,
                self.params.audio_ssrc,
                Suite::Audio,
            ),
            rid: None,
        };
        let mut vclock = Clock {
            base: rand::random(),
            origin: None,
            last: 0,
        };
        let mut aclock: u32 = rand::random();
        // Audio: ffmpeg A-law (stdin) -> Opus RTP over loopback.
        let opus_sock = UdpSocket::bind("127.0.0.1:0").await?;
        let mut ffmpeg: Option<Ffmpeg> = None;
        let mut opus_buf = vec![0u8; 2048];
        let mut stats = (0u64, 0u64);
        let started = Instant::now();

        loop {
            let timeout = loop {
                match self.rtc.poll_output()? {
                    Output::Timeout(t) => break t,
                    Output::Transmit(t) => {
                        let _ = self.sock.send_to(&t.contents, t.destination).await;
                    }
                    Output::Event(e) => match e {
                        Event::Connected => {
                            tracing::info!(
                                "WebRTC {}: connected after {:.1} s",
                                short(&sid),
                                started.elapsed().as_secs_f32()
                            );
                            let (backlog, rx) = self.video.subscribe();
                            for f in backlog {
                                need_key = false;
                                let ts = vclock.ts(f.pts90k);
                                vtx.send(
                                    &mut self.rtc,
                                    &annexb_to_length_prefixed(&f.annexb),
                                    ts,
                                    true,
                                );
                                stats.0 += 1;
                            }
                            video_rx = Some(rx);
                            if self.audio.info().is_some_and(|i| i.has_audio_alaw) {
                                audio_rx = Some(self.audio.subscribe_audio());
                                match spawn_opus(&opus_sock) {
                                    Ok(f) => ffmpeg = Some(f),
                                    Err(e) => tracing::warn!(
                                        "WebRTC {}: no audio (ffmpeg): {e:#}",
                                        short(&sid)
                                    ),
                                }
                            }
                        }
                        Event::IceConnectionStateChange(IceConnectionState::Disconnected) => {
                            tracing::info!("WebRTC {}: ICE desconectado", short(&sid));
                            return Ok(());
                        }
                        Event::IceConnectionStateChange(s) => {
                            tracing::info!("WebRTC {}: ICE {s:?}", short(&sid));
                        }
                        Event::KeyframeRequest(k) => {
                            // FIR/PLI: resend the last keyframe now (max one per 500 ms).
                            tracing::info!("WebRTC {}: {:?} from receiver", short(&sid), k.kind);
                            if last_key.is_none_or(|t| t.elapsed() > Duration::from_millis(500))
                                && let Some(f) = self.video.latest_keyframe()
                            {
                                last_key = Some(Instant::now());
                                // Same instant as the last frame sent, +1 to keep it increasing.
                                let ts = vclock.last.wrapping_add(1);
                                vclock.last = ts;
                                vtx.send(
                                    &mut self.rtc,
                                    &annexb_to_length_prefixed(&f.annexb),
                                    ts,
                                    true,
                                );
                                stats.0 += 1;
                                need_key = false;
                            }
                        }
                        Event::MediaEgressStats(m) => tracing::info!(
                            "WebRTC {}: {:?} sent {} pkts {} B, nacks {} plis {} firs {}, rtt {:?}, loss {:?}",
                            short(&sid),
                            m.mid,
                            m.packets,
                            m.bytes,
                            m.nacks,
                            m.plis,
                            m.firs,
                            m.rtt,
                            m.loss
                        ),
                        other => tracing::debug!("WebRTC {}: {other:?}", short(&sid)),
                    },
                }
            };
            if !self.rtc.is_alive() {
                return Ok(());
            }
            let wait = timeout.saturating_duration_since(Instant::now());
            tokio::select! {
                _ = self.cancel.notified() => {
                    tracing::info!(
                        "WebRTC {}: stop requested; {} video frames and {} audio packets sent",
                        short(&sid), stats.0, stats.1
                    );
                    return Ok(());
                }
                r = self.sock.recv_from(&mut buf) => {
                    let (n, source) = r?;
                    let recv = Receive {
                        proto: Protocol::Udp,
                        source,
                        destination: self.local,
                        contents: (&buf[..n]).try_into()?,
                    };
                    self.rtc.handle_input(Input::Receive(Instant::now(), recv))?;
                }
                _ = tokio::time::sleep(wait) => {
                    self.rtc.handle_input(Input::Timeout(Instant::now()))?;
                }
                f = recv_opt(&mut video_rx) => {
                    match f {
                        Ok(f) => {
                            if need_key && !f.keyframe { continue; }
                            need_key = false;
                            let ts = vclock.ts(f.pts90k);
                            vtx.send(&mut self.rtc, &annexb_to_length_prefixed(&f.annexb), ts, true);
                            stats.0 += 1;
                            self.rtc.handle_input(Input::Timeout(Instant::now()))?;
                        }
                        Err(broadcast::error::RecvError::Lagged(_)) => need_key = true,
                        Err(broadcast::error::RecvError::Closed) => {
                            tracing::info!("WebRTC {}: camera disconnected", short(&sid));
                            return Ok(());
                        }
                    }
                }
                a = recv_opt(&mut audio_rx) => {
                    if let (Ok(a), Some(ff)) = (a, ffmpeg.as_mut()) {
                        let _ = ff.write(&a.alaw).await;
                    }
                }
                r = opus_sock.recv_from(&mut opus_buf), if ffmpeg.is_some() => {
                    let (n, _) = r?;
                    // ffmpeg RTP header: 12 bytes (+CSRC); the rest is an Opus frame.
                    if n > 12 {
                        let cc = (opus_buf[0] & 0x0f) as usize;
                        let off = 12 + 4 * cc;
                        if n > off {
                            atx.send(&mut self.rtc, &opus_buf[off..n], aclock, false);
                            aclock = aclock.wrapping_add(960);
                            stats.1 += 1;
                            self.rtc.handle_input(Input::Timeout(Instant::now()))?;
                        }
                    }
                }
            }
        }
    }
}

/// `recv` of an optional receiver; without a receiver it never resolves.
async fn recv_opt<T: Clone>(
    rx: &mut Option<broadcast::Receiver<T>>,
) -> Result<T, broadcast::error::RecvError> {
    match rx {
        Some(r) => r.recv().await,
        None => std::future::pending().await,
    }
}

/// ffmpeg: A-law 8 kHz on stdin -> Opus 48 kHz mono 20 ms, RTP to the loopback socket.
fn spawn_opus(sock: &UdpSocket) -> Result<Ffmpeg> {
    let port = sock.local_addr()?.port();
    let args = [
        "-f",
        "alaw",
        "-ar",
        "8000",
        "-ac",
        "1",
        "-i",
        "pipe:0",
        "-c:a",
        "libopus",
        "-application",
        "lowdelay",
        "-ar",
        "48000",
        "-ac",
        "1",
        "-b:a",
        "24k",
        "-frame_duration",
        "20",
        "-payload_type",
        "110",
        "-f",
        "rtp",
    ]
    .map(String::from)
    .into_iter()
    .chain([format!("rtp://127.0.0.1:{port}?pkt_size=1200")])
    .collect();
    Ffmpeg::spawn(args)
}

// ---------------------------------------------------------------- TLV

/// Solicit Offer: `SFrame Enabled` option (None if absent).
pub fn parse_solicit(raw: &[u8]) -> Option<bool> {
    let t = Tlv8::parse(raw).ok()?;
    let o = Tlv8::parse(t.get(1)?).ok()?;
    o.get_u8(1).ok().flatten().map(|v| v != 0)
}

pub fn solicit_response(s: &Solicited) -> Vec<u8> {
    let mut t = Tlv8::new().push(1, &s.sid).push(2, s.sdp.as_bytes());
    // Candidate list (tag 3) empty: candidates go inside the SDP.
    t = t.push_u8(4, SO_SUCCESS);
    if let Some((key, kid)) = &s.sframe {
        let k = Tlv8::new().push(1, key).push_u64(2, *kid).encode();
        t = t.push(5, &k);
    }
    t.encode()
}

pub fn solicit_error(status: u8) -> Vec<u8> {
    Tlv8::new().push_u8(4, status).encode()
}

pub fn status_tlv(sid: Option<&Sid>, status: u8) -> Vec<u8> {
    let t = match sid {
        Some(s) => Tlv8::new().push(1, s),
        None => Tlv8::new(),
    };
    t.push_u8(2, status).encode()
}

pub fn parse_sid(t: &Tlv8) -> Option<Sid> {
    t.get(1)?.try_into().ok()
}

/// (sid, sdp, candidates) from Provide Answer.
pub fn parse_answer_tlv(raw: &[u8]) -> Option<(Sid, String, Vec<String>)> {
    let t = Tlv8::parse(raw).ok()?;
    let sdp = String::from_utf8(t.get(2)?.to_vec()).ok()?;
    let cands = t
        .get_all(3)
        .into_iter()
        .filter_map(|c| {
            let c = Tlv8::parse(c).ok()?;
            String::from_utf8(c.get(1)?.to_vec()).ok()
        })
        .collect();
    Some((parse_sid(&t)?, sdp, cands))
}

pub fn reoffer_response(sid: &Sid, r: Result<String, u8>) -> Vec<u8> {
    match r {
        Ok(sdp) => Tlv8::new()
            .push(1, sid)
            .push(2, sdp.as_bytes())
            .push_u8(3, ST_SUCCESS)
            .encode(),
        Err(st) => Tlv8::new().push(1, sid).push_u8(3, st).encode(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use std::sync::atomic::{AtomicU8, Ordering};

    fn tier() -> Tier {
        super::super::tiers_for(
            &crate::media::StreamInfo {
                width: 2560,
                height: 1440,
                fps: 12.0,
                has_audio_alaw: true,
            },
            &crate::media::StreamInfo {
                width: 640,
                height: 360,
                fps: 12.0,
                has_audio_alaw: true,
            },
        )
        .into_iter()
        .find(|t| t.source == super::super::tiers::TierSource::SubCopy)
        .unwrap()
    }

    fn webrtc() -> (Arc<WebRtc>, Arc<AtomicU8>) {
        let n = Arc::new(AtomicU8::new(0));
        let n2 = n.clone();
        let w = WebRtc::new(
            Stream::detached(),
            Stream::detached(),
            tier(),
            Arc::new(move |c| n2.store(c, Ordering::SeqCst)),
        );
        (w, n)
    }

    const ANSWER: &str = "v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n\
        a=group:BUNDLE 0 1\r\nm=video 9 UDP/TLS/RTP/SAVPF 99\r\nc=IN IP4 0.0.0.0\r\n\
        a=ice-ufrag:abcd\r\na=ice-pwd:0123456789012345678901\r\n\
        a=fingerprint:sha-256 00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF\r\n\
        a=setup:active\r\na=mid:0\r\na=recvonly\r\na=rtcp-mux\r\na=rtpmap:99 H265/90000\r\n\
        m=audio 9 UDP/TLS/RTP/SAVPF 110\r\nc=IN IP4 0.0.0.0\r\na=mid:1\r\na=recvonly\r\n";

    #[tokio::test]
    async fn solicit_offer_response_tlv() {
        let (w, _) = webrtc();
        let s = w.solicit(None).unwrap();
        assert!(s.sdp.contains("H265/90000") && s.sdp.contains("opus/48000/2"));
        assert!(s.sdp.contains("m=video 9 UDP/TLS/RTP/SAVPF 99"));
        assert!(s.sdp.contains("a=rid:1 send max-width=640;max-height=360"));
        assert!(s.sdp.contains("a=candidate:") && s.sdp.contains("a=fingerprint:sha-256 "));
        assert!(s.sdp.contains("a=setup:actpass"));
        let t = Tlv8::parse(&solicit_response(&s)).unwrap();
        assert_eq!(t.get(1).unwrap(), s.sid);
        assert_eq!(t.get_u8(4).unwrap(), Some(SO_SUCCESS));
        assert_eq!(t.get(2).unwrap(), s.sdp.as_bytes());
        assert!(t.get(3).is_none());
        let k = Tlv8::parse(t.get(5).unwrap()).unwrap();
        assert_eq!(k.get(1).unwrap().len(), 32);
        assert_eq!(k.get_u64(2).unwrap(), Some(SENDER_KID));
    }

    #[tokio::test]
    async fn max_six_sessions() {
        let (w, _) = webrtc();
        for _ in 0..MAX_SESSIONS {
            w.solicit(None).unwrap();
        }
        assert!(w.solicit(None).is_err());
    }

    #[tokio::test]
    async fn answer_activates_and_end_decrements_and_notifies() {
        let (w, n) = webrtc();
        let s = w.solicit(None).unwrap();
        assert_eq!(w.answer(s.sid, ANSWER, &[]), ST_SUCCESS);
        assert_eq!(w.active(), 1);
        assert_eq!(n.load(Ordering::SeqCst), 1);
        // a second answer for the same session is Error
        assert_eq!(w.answer(s.sid, ANSWER, &[]), ST_ERROR);
        assert_eq!(w.update(&s.sid, 1, 0), ST_SUCCESS);
        assert!(w.reoffer(&s.sid, ANSWER).is_ok());
        assert_eq!(w.end(&s.sid), ST_SUCCESS);
        assert_eq!(w.active(), 0);
        assert_eq!(n.load(Ordering::SeqCst), 0);
        assert_eq!(w.end(&s.sid), ST_UNKNOWN);
        assert_eq!(w.answer([9; 16], ANSWER, &[]), ST_UNKNOWN);
    }

    #[test]
    fn answer_parsing_and_bad_answers() {
        let a = parse_answer(
            ANSWER,
            &["a=candidate:1 1 udp 2113937151 10.0.0.2 5000 typ host".into()],
        )
        .unwrap();
        assert_eq!((a.ufrag.as_str(), a.setup.as_str()), ("abcd", "active"));
        assert_eq!(a.candidates.len(), 1);
        assert!(a.candidates[0].starts_with("candidate:1 1 udp"));
        assert!(parse_answer("v=0\r\n", &[]).is_err());
    }

    #[test]
    fn reanswer_keeps_our_mids_and_rejects_others() {
        let p = SdpParams {
            ufrag: "u".into(),
            pwd: "p".into(),
            fingerprint: "sha-256 AA".into(),
            video_ssrc: 1,
            audio_ssrc: 2,
            tier: tier(),
            candidates: vec![],
        };
        let offer = format!("{ANSWER}m=audio 9 UDP/TLS/RTP/SAVPF 111\r\na=mid:2\r\na=sendrecv\r\n");
        let ans = build_reanswer(&p, false, &offer).unwrap();
        assert!(ans.contains("a=group:BUNDLE 0 1\r\n"));
        assert!(ans.contains("m=audio 0 UDP/TLS/RTP/SAVPF 111"));
        assert!(ans.contains("a=setup:passive"));
    }

    #[test]
    fn annexb_conversion() {
        let au = [
            0, 0, 0, 1, 0x40, 1, 2, 0, 0, 1, 0x42, 1, 3, 4, 0, 0, 0, 1, 0x26, 1, 9,
        ];
        let out = annexb_to_length_prefixed(&au);
        assert_eq!(
            out,
            [
                0, 0, 0, 3, 0x40, 1, 2, 0, 0, 0, 4, 0x42, 1, 3, 4, 0, 0, 0, 3, 0x26, 1, 9
            ]
        );
    }

    #[test]
    fn clock_is_monotonic_across_pts_reset() {
        let mut c = Clock {
            base: 1000,
            origin: None,
            last: 0,
        };
        assert_eq!(c.ts(500), 1000);
        assert_eq!(c.ts(3500), 4000);
        let after_reset = c.ts(0);
        assert!(after_reset > 4000);
        assert!(c.ts(3600) > after_reset);
    }

    #[test]
    fn solicit_options_parse() {
        let on = Tlv8::new()
            .push(1, &Tlv8::new().push_u8(1, 1).encode())
            .encode();
        assert_eq!(parse_solicit(&on), Some(true));
        assert_eq!(parse_solicit(&[]), None);
    }

    /// Fake controller using str0m: answers our offer, connects over loopback (ICE, DTLS,
    /// SRTP), and must receive SFrame video decryptable with the offer's key.
    #[tokio::test]
    async fn loopback_controller_receives_sframe_video() {
        use str0m::IceCreds;
        use str0m::rtp::SeqNo;
        let (w, _) = webrtc();
        let sub = w.sub.clone();
        let sol = w
            .solicit(Some(ConnAddrs {
                peer: "127.0.0.1:1".parse().unwrap(),
                local: "127.0.0.1:2".parse().unwrap(),
            }))
            .unwrap();
        let offer = parse_answer(&sol.sdp, &[]).unwrap(); // the offer has the same ICE fields
        // Controller: socket, Rtc, its own credentials.
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let caddr = sock.local_addr().unwrap();
        let mut crtc = rtc_config().set_rtp_mode(true).build(Instant::now());
        let (creds, fp) = {
            let mut d = crtc.direct_api();
            d.set_ice_controlling(false);
            (
                d.local_ice_credentials(),
                d.local_dtls_fingerprint().to_string(),
            )
        };
        crtc.add_local_candidate(Candidate::host(caddr, "udp").unwrap());
        {
            let mut d = crtc.direct_api();
            d.declare_media("0".into(), MediaKind::Video);
            d.declare_media("1".into(), MediaKind::Audio);
            let vs: Ssrc = parse_ssrc(&sol.sdp, "video").into();
            let (v, a) = (vs, Ssrc::from(parse_ssrc(&sol.sdp, "audio")));
            d.expect_stream_rx(v, None, "0".into(), None);
            d.expect_stream_rx(a, None, "1".into(), None);
            d.set_remote_ice_credentials(IceCreds {
                ufrag: offer.ufrag.clone(),
                pass: offer.pwd.clone(),
            });
            d.set_remote_fingerprint(offer.fingerprint.parse().unwrap());
            d.start_dtls(true).unwrap(); // controlador activo, accesorio servidor
        }
        for c in &offer.candidates {
            crtc.add_remote_candidate(Candidate::from_sdp_string(c).unwrap());
        }
        crtc.handle_input(Input::Timeout(Instant::now())).unwrap();
        let answer = ANSWER
            .replace("abcd", &creds.ufrag)
            .replace("0123456789012345678901", &creds.pass)
            .replace(
                "00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF",
                fp.trim_start_matches("sha-256 "),
            );
        assert_eq!(
            w.answer(
                sol.sid,
                &answer,
                &[format!(
                    "candidate:1 1 udp 2113937151 {} {} typ host",
                    caddr.ip(),
                    caddr.port()
                )]
            ),
            ST_SUCCESS
        );
        // Frames: one fake keyframe (VPS/SPS/PPS + IDR) per second of test.
        let frame = |pts| Frame {
            pts90k: pts,
            keyframe: true,
            annexb: Bytes::from(
                [
                    &[0, 0, 0, 1, 0x40, 1, 9][..],
                    &[0, 0, 0, 1, 0x26, 1],
                    &[7u8; 3000][..],
                ]
                .concat(),
            ),
        };
        let mut seen: Vec<str0m::rtp::RtpPacket> = Vec::new();
        let mut buf = vec![0u8; 2048];
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut pts = 0;
        while Instant::now() < deadline && !seen.iter().any(|p| p.payload[0] & 0x40 != 0) {
            loop {
                match crtc.poll_output().unwrap() {
                    Output::Timeout(_) => break,
                    Output::Transmit(t) => {
                        let _ = sock.send_to(&t.contents, t.destination).await;
                    }
                    Output::Event(Event::RtpPacket(p)) => seen.push(p),
                    Output::Event(_) => {}
                }
            }
            sub.push_frame(frame(pts));
            pts += 3600;
            tokio::select! {
                r = sock.recv_from(&mut buf) => {
                    let (n, source) = r.unwrap();
                    let recv = Receive { proto: Protocol::Udp, source, destination: caddr, contents: (&buf[..n]).try_into().unwrap() };
                    crtc.handle_input(Input::Receive(Instant::now(), recv)).unwrap();
                }
                _ = tokio::time::sleep(Duration::from_millis(40)) => {
                    crtc.handle_input(Input::Timeout(Instant::now())).unwrap();
                }
            }
        }
        let _ = SeqNo::from(0u64);
        assert!(!seen.is_empty(), "controller did not receive RTP");
        let first = &seen[0];
        assert_eq!(*first.header.payload_type, VIDEO_PT);
        assert_eq!(
            first.payload[0] & 0x80,
            0x80,
            "S descriptor of the first chunk"
        );
        // decrypt the full frame with the offer's key and check the length prefix
        let (key, kid) = sol.sframe.clone().unwrap();
        let mut sealed = Vec::new();
        for p in &seen {
            sealed.extend_from_slice(&p.payload[1..]);
            if p.payload[0] & 0x40 != 0 {
                break;
            }
        }
        assert!(
            sealed.len() > 3000,
            "frame completo en {} bytes",
            sealed.len()
        );
        assert_eq!(kid, SENDER_KID);
        let mut expect = SFrameStream::new(&key, kid, parse_ssrc(&sol.sdp, "video"), Suite::Video);
        let want = expect.protect(&annexb_to_length_prefixed(&frame(0).annexb));
        assert_eq!(sealed, want, "same counter 0 and same content");
        w.end_all();
    }

    fn parse_ssrc(sdp: &str, kind: &str) -> u32 {
        let mut in_kind = false;
        for l in sdp.lines() {
            if l.starts_with("m=") {
                in_kind = l.starts_with(&format!("m={kind}"));
            } else if in_kind && let Some(r) = l.strip_prefix("a=ssrc:") {
                return r.split(' ').next().unwrap().parse().unwrap();
            }
        }
        panic!("no ssrc");
    }

    #[tokio::test]
    #[ignore = "requires ffmpeg with libopus"]
    async fn ffmpeg_converts_alaw_to_opus_rtp() {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut ff = spawn_opus(&sock).unwrap();
        // 1 s of A-law (silence = 0xd5) in 20 ms blocks.
        for _ in 0..50 {
            ff.write(&[0xd5; 160]).await.unwrap();
        }
        let mut buf = [0u8; 2048];
        let mut n = 0;
        let end = Instant::now() + Duration::from_secs(3);
        while Instant::now() < end && n < 20 {
            if let Ok(Ok((len, _))) =
                tokio::time::timeout(Duration::from_millis(500), sock.recv_from(&mut buf)).await
            {
                assert_eq!(buf[1] & 0x7f, 110, "payload type Opus");
                assert!(len > 12 && len < 400);
                n += 1;
            }
        }
        assert!(n >= 20, "only {n} Opus packets");
    }

    #[tokio::test]
    async fn sdp_summary_has_no_secrets_and_offer_has_msid() {
        let (w, _) = webrtc();
        let s = w.solicit(None).unwrap();
        assert!(
            s.sdp.contains("a=msid-semantic: WMS *")
                && s.sdp.contains("msid:hksv-rtsp-bridge video0")
        );
        let sum = sdp_summary(&s.sdp);
        assert!(sum.contains("a=rtpmap:99 H265/90000") && sum.contains("a=rid:1"));
        for secret in ["ice-pwd", "ice-ufrag", "fingerprint", "candidate"] {
            assert!(!sum.contains(secret), "{secret}");
        }
    }
}
