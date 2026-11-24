//! Classic Camera RTP Stream Management (service 110, H.264 + Opus + SRTP).
//!
//! This is what go2rtc publishes (pkg/hap/camera/accessory.go), and what any
//! controller without iOS 27 understands. TLV and semantics follow HAP-NodeJS `RTPStreamManagement.ts`.
//! Setup Endpoints (118) is identical to the Multi-Tier RTP one and reuses `Sessions::prepare`.

use anyhow::{Context, Result, ensure};

use super::rtp_session::{VFR, input_args, video_out_args};
use super::setup_endpoints::EndpointRequest;
use crate::config::{HwAccel, MaxResolution};
use crate::hap::tlv8::Tlv8;

pub const VIDEO_PT: u8 = 99;
pub const AUDIO_PT: u8 = 110;
const CODEC_H264: u8 = 0;
const CODEC_OPUS: u8 = 3;
const PROFILE_MAIN: u8 = 1;
const PROFILE_HIGH: u8 = 2;
const LEVEL_3_1: u8 = 0;
const LEVEL_4_0: u8 = 2;
/// Opus at 16 kHz (HAP enum: 0 = 8 kHz, 1 = 16 kHz, 2 = 24 kHz).
const RATE_16K: u8 = 1;
/// (width, height, fps) advertised; 1280x720 comes from the main stream and 640x360 from the sub.
pub const RESOLUTIONS: [(u16, u16, u8); 2] = [(1280, 720, 25), (640, 360, 25)];

/// TLV8 list: items of the same type separated by the empty type-0 TLV.
fn push_list(mut t: Tlv8, tag: u8, items: &[Vec<u8>]) -> Tlv8 {
    for (i, it) in items.iter().enumerate() {
        if i > 0 {
            t = t.push_sep();
        }
        t = t.push(tag, it);
    }
    t
}

/// Supported Video Stream Configuration (114): H.264 Main/High, levels 3.1/4.0.
pub fn supported_video_tlv(max: MaxResolution) -> Vec<u8> {
    let params = push_list(Tlv8::new(), 1, &[vec![PROFILE_MAIN], vec![PROFILE_HIGH]]);
    let params = push_list(params, 2, &[vec![LEVEL_3_1], vec![LEVEL_4_0]])
        .push_u8(3, 0) // packetization mode 0 = non-interleaved
        .encode();
    // ponytail: 640x360 is the second entry in RESOLUTIONS; "360p" only advertises that one.
    let advertised = match max {
        MaxResolution::P720 => &RESOLUTIONS[..],
        MaxResolution::P360 => &RESOLUTIONS[1..],
    };
    let attrs: Vec<Vec<u8>> = advertised
        .iter()
        .map(|&(w, h, fps)| {
            Tlv8::new()
                .push(1, &w.to_le_bytes())
                .push(2, &h.to_le_bytes())
                .push_u8(3, fps)
                .encode()
        })
        .collect();
    let codec = push_list(
        Tlv8::new().push_u8(1, CODEC_H264).push(2, &params),
        3,
        &attrs,
    )
    .encode();
    Tlv8::new().push(1, &codec).encode()
}

/// Supported Audio Stream Configuration (115): Opus 16 kHz mono, VBR, no comfort noise.
pub fn supported_audio_tlv() -> Vec<u8> {
    let params = Tlv8::new()
        .push_u8(1, 1) // canales
        .push_u8(2, 0) // bitrate variable
        .push_u8(3, RATE_16K)
        .encode();
    let codec = Tlv8::new().push_u8(1, CODEC_OPUS).push(2, &params).encode();
    Tlv8::new().push(1, &codec).push_u8(2, 0).encode()
}

/// Streaming Status (120): 0 = available, 1 = in use, 2 = unavailable.
pub fn streaming_status_tlv(status: u8) -> Vec<u8> {
    Tlv8::new().push_u8(1, status).encode()
}

#[derive(Clone, Debug, PartialEq)]
pub struct VideoSel {
    pub width: u16,
    pub height: u16,
    pub fps: u8,
    /// 0 = baseline, 1 = main, 2 = high.
    pub profile: u8,
    /// 0 = 3.1, 1 = 3.2, 2 = 4.0.
    pub level: u8,
    pub pt: u8,
    pub max_kbps: u16,
    pub mtu: u16,
}

#[derive(Clone, Debug, PartialEq)]
pub struct AudioSel {
    pub pt: u8,
    pub max_kbps: u16,
    pub sample_khz: u32,
    pub frame_ms: u32,
}

/// Selected RTP Stream Configuration (117) from a Start/Reconfigure.
#[derive(Clone, Debug, PartialEq)]
pub struct SelectedConfig {
    pub session_id: [u8; 16],
    pub video: VideoSel,
    pub audio: Option<AudioSel>,
}

/// Session Control of 117: (session id, command: 0 end, 1 start, 2 suspend, 3 resume, 4 reconfigure).
pub fn parse_control(raw: &[u8]) -> Result<([u8; 16], u8)> {
    let t = Tlv8::parse(raw)?;
    let c = Tlv8::parse(t.get(1).context("missing Session Control")?)?;
    let sid = c
        .get(1)
        .and_then(|s| s.try_into().ok())
        .context("session id missing or invalid length")?;
    Ok((sid, c.get_u8(2)?.context("missing command")?))
}

/// Video parameters of a Reconfigure (command 4): iOS sends only what changes
/// (resolution and/or RTP attributes), without codec or profile.
#[derive(Debug, Default, PartialEq)]
pub struct Reconfigure {
    pub width: Option<u16>,
    pub height: Option<u16>,
    pub fps: Option<u8>,
    pub max_kbps: Option<u16>,
}

/// Lenient parsing: everything is optional and an unreadable sub-TLV is ignored.
pub fn parse_reconfigure(raw: &[u8]) -> Result<Reconfigure> {
    let t = Tlv8::parse(raw)?;
    let sub = |t: &Tlv8, tag| t.get(tag).and_then(|b| Tlv8::parse(b).ok());
    let v = sub(&t, 2);
    let attrs = v.as_ref().and_then(|v| sub(v, 3));
    let rtp = v.as_ref().and_then(|v| sub(v, 4));
    let get16 = |t: &Option<Tlv8>, tag| t.as_ref().and_then(|t| t.get_u16(tag).ok().flatten());
    Ok(Reconfigure {
        width: get16(&attrs, 1),
        height: get16(&attrs, 2),
        fps: attrs.as_ref().and_then(|t| t.get_u8(3).ok().flatten()),
        max_kbps: get16(&rtp, 3),
    })
}

pub fn parse_selected(raw: &[u8]) -> Result<SelectedConfig> {
    let (session_id, _) = parse_control(raw)?;
    let t = Tlv8::parse(raw)?;
    let v = Tlv8::parse(t.get(2).context("missing video config")?)?;
    let vp = Tlv8::parse(v.get(2).context("missing video parameters")?)?;
    let va = Tlv8::parse(v.get(3).context("missing video attributes")?)?;
    let vr = Tlv8::parse(v.get(4).context("missing video RTP parameters")?)?;
    ensure!(
        v.get_u8(1)? == Some(CODEC_H264),
        "codec de video distinto de H.264"
    );
    let video = VideoSel {
        width: va.get_u16(1)?.context("missing width")?,
        height: va.get_u16(2)?.context("missing height")?,
        fps: va.get_u8(3)?.unwrap_or(25).clamp(1, 30),
        profile: vp.get_u8(1)?.unwrap_or(PROFILE_MAIN),
        level: vp.get_u8(2)?.unwrap_or(LEVEL_3_1),
        pt: vr.get_u8(1)?.unwrap_or(VIDEO_PT),
        max_kbps: vr.get_u16(3)?.unwrap_or(0),
        // Guide default: 1378 (IPv4).
        mtu: vr.get_u16(5)?.unwrap_or(1378),
    };
    ensure!(video.width > 0 && video.height > 0, "dimensiones 0");
    let audio = match t.get(3) {
        Some(a) => {
            let a = Tlv8::parse(a)?;
            let ap = Tlv8::parse(a.get(2).context("missing audio parameters")?)?;
            let ar = Tlv8::parse(a.get(3).context("missing audio RTP parameters")?)?;
            (a.get_u8(1)? == Some(CODEC_OPUS)).then(|| AudioSel {
                pt: ar.get_u8(1).ok().flatten().unwrap_or(AUDIO_PT),
                max_kbps: ar.get_u16(3).ok().flatten().unwrap_or(24),
                sample_khz: match ap.get_u8(3).ok().flatten() {
                    Some(0) => 8,
                    Some(2) => 24,
                    _ => 16,
                },
                // libopus only supports 20/40/60 ms of the HAP values (20/30/40/60).
                frame_ms: match ap.get_u8(4).ok().flatten() {
                    Some(m @ (40 | 60)) => u32::from(m),
                    _ => 20,
                },
            })
        }
        None => None,
    };
    Ok(SelectedConfig {
        session_id,
        video,
        audio,
    })
}

impl VideoSel {
    /// 640x360 or smaller comes from the sub stream (cheap: it decodes 360p); anything else comes from the main stream only with
    /// `hwaccel = "vaapi"`. On CPU, 1280x720 would force decoding 2K HEVC and re-encoding to
    /// H.264 (on an i3-2120 it is very heavy and live video never reached a direct iPhone), so
    /// it is upscaled from the sub stream: at 299 kbps there is no extra detail to use.
    pub fn uses_sub(&self) -> bool {
        self.height <= 360
    }
}

fn profile_name(p: u8) -> &'static str {
    match p {
        0 => "baseline",
        2 => "high",
        _ => "main",
    }
}

fn level_name(l: u8) -> &'static str {
    match l {
        1 => "3.2",
        2 => "4.0",
        _ => "3.1",
    }
}

/// ffmpeg: HEVC (Annex B on stdin) -> H.264 (+ Opus) -> SRTP to the controller.
/// 640x360 is read from the sub stream and 1280x720 from the main stream (the caller picks the stream with `uses_sub`).
/// The SSRC is the one advertised in Setup Endpoints. Audio goes in another ffmpeg (`audio_ffmpeg_args`).
pub fn legacy_ffmpeg_args(
    sel: &SelectedConfig,
    ep: &EndpointRequest,
    video_ssrc: u32,
    hw: HwAccel,
) -> Vec<String> {
    let v = &sel.video;
    let mut a = input_args();
    let mut add = |xs: &[&str]| a.extend(xs.iter().map(|s| s.to_string()));
    let kbps = if v.max_kbps == 0 {
        600
    } else {
        v.max_kbps.max(100)
    };
    let (profile, level) = (profile_name(v.profile), level_name(v.level));
    let (w, h) = (v.width, v.height);
    add(&["-map", "0:v:0"]);
    add(&VFR); // see VFR: without this the video RTP clock drifts relative to audio
    match hw {
        HwAccel::None => {
            add(&[
                "-c:v",
                "libx264",
                "-preset",
                "ultrafast",
                "-tune",
                "zerolatency",
            ]);
            add(&["-vf", &format!("scale={w}:{h}"), "-pix_fmt", "yuv420p"]);
            add(&["-profile:v", profile, "-level:v", level]);
            // SPS/PPS on every keyframe: HAP's RTP carries no SDP.
            add(&["-x264-params", "repeat-headers=1"]);
        }
        HwAccel::Vaapi => {
            add(&["-vaapi_device", "/dev/dri/renderD128"]);
            add(&[
                "-vf",
                &format!("format=nv12,hwupload,scale_vaapi=w={w}:h={h}"),
            ]);
            add(&["-c:v", "h264_vaapi", "-profile:v", profile, "-level", level]);
            add(&["-bsf:v", "dump_extra=freq=keyframe"]);
        }
    }
    add(&[
        "-b:v",
        &format!("{kbps}k"),
        "-maxrate",
        &format!("{kbps}k"),
        "-bufsize",
        &format!("{}k", kbps * 2),
        "-g",
        &(u32::from(v.fps) * 2).to_string(),
    ]);
    a.extend(video_out_args(ep, v.pt, video_ssrc, v.mtu));
    a
}

/// Name and status key of the separate H.264 accessory.
pub fn separate_name(name: &str) -> String {
    format!("{name} (H.264)")
}

pub fn separate_key(slug: &str) -> String {
    format!("{slug}-legacy")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::camera::rtp_session::{AudioOut, audio_ffmpeg_args};
    use crate::camera::setup_endpoints::parse_request;

    const FIXTURE: &[u8] = include_bytes!("../../tests/fixtures/setup_endpoints.tlv");

    fn sel(w: u16, h: u16, audio: bool) -> SelectedConfig {
        SelectedConfig {
            session_id: [1; 16],
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
            audio: audio.then_some(AudioSel {
                pt: 110,
                max_kbps: 24,
                sample_khz: 16,
                frame_ms: 20,
            }),
        }
    }

    fn args(s: &SelectedConfig, hw: HwAccel) -> String {
        let ep = parse_request(FIXTURE).unwrap();
        legacy_ffmpeg_args(s, &ep, 7, hw).join(" ")
    }

    #[test]
    fn legacy_supported_video_tlv() {
        let t = Tlv8::parse(&supported_video_tlv(MaxResolution::P720)).unwrap();
        let c = Tlv8::parse(t.get(1).unwrap()).unwrap();
        assert_eq!(c.get_u8(1).unwrap(), Some(0)); // H.264
        let p = Tlv8::parse(c.get(2).unwrap()).unwrap();
        assert_eq!(p.get_all(1), [&[1u8][..], &[2][..]]); // Main, High
        assert_eq!(p.get_all(2), [&[0u8][..], &[2][..]]); // 3.1, 4.0
        assert_eq!(p.get_u8(3).unwrap(), Some(0));
        let dims: Vec<_> = c
            .get_all(3)
            .iter()
            .map(|a| {
                let a = Tlv8::parse(a).unwrap();
                (
                    a.get_u16(1).unwrap().unwrap(),
                    a.get_u16(2).unwrap().unwrap(),
                    a.get_u8(3).unwrap().unwrap(),
                )
            })
            .collect();
        assert_eq!(dims, [(1280, 720, 25), (640, 360, 25)]);

        // 360p: only 640x360 in the advertised resolution list.
        let t = Tlv8::parse(&supported_video_tlv(MaxResolution::P360)).unwrap();
        let c = Tlv8::parse(t.get(1).unwrap()).unwrap();
        let attrs = c.get_all(3);
        assert_eq!(attrs.len(), 1);
        let a = Tlv8::parse(attrs[0]).unwrap();
        assert_eq!(a.get_u16(1).unwrap(), Some(640));
        assert_eq!(a.get_u16(2).unwrap(), Some(360));
    }

    #[test]
    fn legacy_supported_audio_and_rtp_tlv() {
        let t = Tlv8::parse(&supported_audio_tlv()).unwrap();
        let c = Tlv8::parse(t.get(1).unwrap()).unwrap();
        assert_eq!(c.get_u8(1).unwrap(), Some(3)); // Opus
        let p = Tlv8::parse(c.get(2).unwrap()).unwrap();
        assert_eq!(p.get_u8(1).unwrap(), Some(1));
        assert_eq!(p.get_u8(3).unwrap(), Some(1)); // 16 kHz
        assert_eq!(streaming_status_tlv(0), [1, 1, 0]);
    }

    #[test]
    fn legacy_args_360_uses_sub_and_x264() {
        let s = sel(640, 360, false);
        assert!(s.video.uses_sub());
        assert!(!sel(1280, 720, false).video.uses_sub());
        let a = args(&s, HwAccel::None);
        assert!(a.contains("-c:v libx264") && a.contains("-preset ultrafast"));
        assert!(a.contains("-tune zerolatency") && a.contains("scale=640:360"));
        assert!(a.contains("-profile:v main -level:v 3.1"));
        assert!(a.contains("-b:v 299k"));
        // Regressions found in the real test: no nobuffer (it loses the first IDR) and vfr timestamps.
        assert!(!a.contains("nobuffer"), "{a}");
        assert!(a.contains("-fps_mode vfr -enc_time_base 1:90000"), "{a}");
        assert!(a.contains("-payload_type 99 -ssrc 7"));
        assert!(a.contains("srtp://192.168.50.18:56941?rtcpport=56941&pkt_size=1378"));
        assert!(!a.contains("libopus") && !a.contains("h264_vaapi"));
    }

    #[test]
    fn legacy_args_vaapi() {
        let a = args(&sel(1280, 720, false), HwAccel::Vaapi);
        assert!(a.contains("h264_vaapi") && a.contains("/dev/dri/renderD128"));
        assert!(a.contains("format=nv12,hwupload,scale_vaapi=w=1280:h=720"));
        assert!(!a.contains("libx264"));
    }

    #[test]
    fn legacy_video_args_have_no_audio_and_audio_is_separate() {
        let s = sel(640, 360, true);
        let a = args(&s, HwAccel::None);
        assert!(!a.contains("alaw") && !a.contains("libopus") && !a.contains("-map 1:a:0"));
        let ep = parse_request(FIXTURE).unwrap();
        let au = s.audio.as_ref().unwrap();
        let out = AudioOut {
            pt: au.pt,
            ar: au.sample_khz * 1000,
            kbps: u32::from(au.max_kbps),
            frame_ms: au.frame_ms,
        };
        let a = audio_ffmpeg_args(&ep, &out, 8).join(" ");
        assert!(a.contains("-f alaw -ar 8000 -ac 1 -i pipe:0"));
        assert!(a.contains("libopus") && a.contains("-ar 16000") && a.contains("-b:a 24k"));
        assert!(a.contains("-payload_type 110 -ssrc 8"));
    }

    fn selected_tlv(cmd: u8, kbps: u16, with_audio: bool) -> Vec<u8> {
        let ctl = Tlv8::new().push(1, &[9; 16]).push_u8(2, cmd).encode();
        let vparams = Tlv8::new()
            .push_u8(1, 2)
            .push_u8(2, 2)
            .push_u8(3, 0)
            .encode();
        let vattrs = Tlv8::new()
            .push(1, &1280u16.to_le_bytes())
            .push(2, &720u16.to_le_bytes())
            .push_u8(3, 30)
            .encode();
        let vrtp = Tlv8::new()
            .push_u8(1, 99)
            .push_u32(2, 0xdead)
            .push(3, &kbps.to_le_bytes())
            .push(4, &0.5f32.to_le_bytes())
            .push(5, &1378u16.to_le_bytes())
            .encode();
        let video = Tlv8::new()
            .push_u8(1, 0)
            .push(2, &vparams)
            .push(3, &vattrs)
            .push(4, &vrtp)
            .encode();
        let t = Tlv8::new().push(1, &ctl).push(2, &video);
        if !with_audio {
            return t.encode();
        }
        let aparams = Tlv8::new()
            .push_u8(1, 1)
            .push_u8(2, 0)
            .push_u8(3, 1)
            .push_u8(4, 30)
            .encode();
        let artp = Tlv8::new()
            .push_u8(1, 110)
            .push_u32(2, 0xbeef)
            .push(3, &24u16.to_le_bytes())
            .push(4, &5f32.to_le_bytes())
            .push_u8(6, 13)
            .encode();
        let audio = Tlv8::new()
            .push_u8(1, 3)
            .push(2, &aparams)
            .push(3, &artp)
            .push_u8(4, 0)
            .encode();
        t.push(3, &audio).encode()
    }

    #[test]
    fn parse_selected_start() {
        let s = parse_selected(&selected_tlv(1, 802, true)).unwrap();
        assert_eq!(s.session_id, [9; 16]);
        assert_eq!(
            (s.video.width, s.video.height, s.video.fps),
            (1280, 720, 30)
        );
        assert_eq!((s.video.profile, s.video.level), (2, 2));
        assert_eq!((s.video.pt, s.video.max_kbps, s.video.mtu), (99, 802, 1378));
        let a = s.audio.unwrap();
        // 30 ms does not exist in libopus: lowered to 20.
        assert_eq!(
            (a.pt, a.sample_khz, a.frame_ms, a.max_kbps),
            (110, 16, 20, 24)
        );
        assert_eq!(
            parse_control(&selected_tlv(1, 1, false)).unwrap(),
            ([9; 16], 1)
        );
    }

    /// Real iOS capture: Reconfigure with no codec or parameters, only 640x360@30 and max 132 kbps.
    #[test]
    fn parse_reconfigure_partial_capture() {
        let mut raw = vec![0x01, 0x15, 0x02, 0x01, 0x04, 0x01, 0x10];
        raw.extend_from_slice(&[0xAB; 16]);
        raw.extend_from_slice(&[
            0x02, 0x19, 0x03, 0x0b, 0x01, 0x02, 0x80, 0x02, 0x02, 0x02, 0x68, 0x01, 0x03, 0x01,
            0x1e, 0x04, 0x0a, 0x03, 0x02, 0x84, 0x00, 0x04, 0x04, 0x00, 0x00, 0x00, 0x00,
        ]);
        assert_eq!(parse_control(&raw).unwrap(), ([0xAB; 16], 4));
        // Start would need codec/parameters; the partial Reconfigure does not.
        assert!(parse_selected(&raw).is_err());
        assert_eq!(
            parse_reconfigure(&raw).unwrap(),
            Reconfigure {
                width: Some(640),
                height: Some(360),
                fps: Some(30),
                max_kbps: Some(132),
            }
        );
    }

    #[test]
    fn parse_selected_end_has_only_control() {
        let ctl = Tlv8::new().push(1, &[4; 16]).push_u8(2, 0).encode();
        let raw = Tlv8::new().push(1, &ctl).encode();
        assert_eq!(parse_control(&raw).unwrap(), ([4; 16], 0));
        assert!(parse_selected(&raw).is_err());
        assert!(parse_control(&raw[..5]).is_err());
    }
}
