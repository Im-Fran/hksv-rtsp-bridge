//! `#[ignore]` harness against the real camera (SPIKE_RTSP_URL / SPIKE_RTSP_MAIN_URL): runs the
//! production classic H.264 session (`Sessions::start_legacy`: same ffmpeg args, VideoFeed
//! and audio ffmpeg) toward local UDP sinks with a dummy SRTP key and measures:
//! (a) ffmpeg HEVC errors, (b) time to first video RTP and whether it starts at an IDR,
//! (c) gaps and timestamp continuity of audio RTP, and (d) retina's raw timing.
//! Environment options: HARNESS_SECS (30), HARNESS_RES=640x360|1280x720 (640x360).
use super::*;
use crate::camera::legacy::{AudioSel, VideoSel};
use crate::camera::setup_endpoints::{SrtpParams, parse_request};
use crate::camera::tiers::tiers_for;
use crate::media::StreamInfo;
use aes::Aes128;
use ctr::Ctr128BE;
use ctr::cipher::{BlockCipherEncrypt, KeyInit, KeyIvInit, StreamCipher};

const KEY: [u8; 16] = [7; 16];
const SALT: [u8; 14] = [9; 14];

fn env(k: &str) -> String {
    std::env::var(k).unwrap_or_else(|_| panic!("missing {k}"))
}

/// SRTP session key and salt (RFC 3711 4.3, index 0).
fn session_keys() -> ([u8; 16], [u8; 14]) {
    let kdf = |label: u8, n: usize| {
        let mut iv = [0u8; 16];
        iv[..14].copy_from_slice(&SALT);
        iv[7] ^= label;
        let mut out = [0u8; 16];
        let mut blk = iv.into();
        Aes128::new((&KEY).into()).encrypt_block(&mut blk);
        out[..n].copy_from_slice(&blk[..n]);
        out
    };
    let (k, s) = (kdf(0, 16), kdf(2, 14));
    (k, s[..14].try_into().unwrap())
}

/// Decrypts an SRTCP Sender Report: (ntp in unix ms, RTP ts). `None` if it is not an SR.
fn unprotect_sr(p: &[u8]) -> Option<(f64, u32)> {
    if p.len() < 8 + 20 + 14 || p[0] >> 6 != 2 || p[1] != 200 {
        return None;
    }
    let kdf = |label: u8, n: usize| {
        let mut iv = [0u8; 16];
        iv[..14].copy_from_slice(&SALT);
        iv[7] ^= label;
        let mut blk = iv.into();
        Aes128::new((&KEY).into()).encrypt_block(&mut blk);
        let o: [u8; 16] = blk.into();
        o[..n].to_vec()
    };
    let (k, salt) = (kdf(3, 16), kdf(5, 14));
    let end = p.len() - 14;
    let mut pay = p[8..end].to_vec();
    let mut iv = [0u8; 16];
    iv[..14].copy_from_slice(&salt);
    for i in 0..4 {
        iv[4 + i] ^= p[4 + i];
        iv[10 + i] ^= p[end + i] & if i == 0 { 0x7f } else { 0xff };
    }
    Ctr128BE::<Aes128>::new(
        (&<[u8; 16]>::try_from(k.as_slice()).unwrap()).into(),
        (&iv).into(),
    )
    .apply_keystream(&mut pay);
    let secs = f64::from(u32::from_be_bytes(pay[0..4].try_into().ok()?)) - 2_208_988_800.0;
    let frac = f64::from(u32::from_be_bytes(pay[4..8].try_into().ok()?)) / 4_294_967_296.0;
    Some((
        (secs + frac) * 1000.0,
        u32::from_be_bytes(pay[8..12].try_into().ok()?),
    ))
}

/// (marker, seq, timestamp, decrypted payload) of an SRTP packet.
fn unprotect(p: &[u8], keys: &([u8; 16], [u8; 14])) -> (bool, u16, u32, Vec<u8>) {
    let seq = u16::from_be_bytes([p[2], p[3]]);
    let ts = u32::from_be_bytes([p[4], p[5], p[6], p[7]]);
    let mut pay = p[12..p.len() - 10].to_vec();
    // IV = (salt << 16) ^ (ssrc << 64) ^ (index << 16); ROC = 0 in tests with fewer than 65536 packets.
    let mut iv2 = [0u8; 16];
    iv2[..14].copy_from_slice(&keys.1);
    for i in 0..4 {
        iv2[4 + i] ^= p[8 + i];
    }
    iv2[12] ^= p[2];
    iv2[13] ^= p[3];
    Ctr128BE::<Aes128>::new((&keys.0).into(), (&iv2).into()).apply_keystream(&mut pay);
    (p[1] & 0x80 != 0, seq, ts, pay)
}

/// H.264 NAL types of an RTP payload (STAP-A, FU-A start, single).
fn h264_nals(pay: &[u8]) -> Vec<u8> {
    match pay.first().map(|b| b & 0x1f) {
        Some(24) => {
            let (mut i, mut v) = (1, vec![]);
            while i + 2 < pay.len() {
                let n = u16::from_be_bytes([pay[i], pay[i + 1]]) as usize;
                v.push(pay[i + 2] & 0x1f);
                i += 2 + n;
            }
            v
        }
        Some(28) if pay.len() > 1 && pay[1] & 0x80 != 0 => vec![pay[1] & 0x1f],
        Some(28) => vec![],
        Some(t) => vec![t],
        None => vec![],
    }
}

fn hevc_nals(a: &[u8]) -> Vec<u8> {
    a.windows(4)
        .filter(|w| w[..3] == [0, 0, 1])
        .map(|w| (w[3] >> 1) & 0x3f)
        .collect()
}

#[derive(Default)]
struct Raw {
    video: Vec<(u128, i64, bool, Vec<u8>)>,
    audio: Vec<(u128, i64, usize)>,
}

#[tokio::test]
#[ignore = "requires a real camera (SPIKE_RTSP_URL, SPIKE_RTSP_MAIN_URL) and ffmpeg"]
async fn live_session_repro() {
    let secs: u64 = std::env::var("HARNESS_SECS").map_or(30, |s| s.parse().unwrap());
    let res = std::env::var("HARNESS_RES").unwrap_or("640x360".into());
    let (w, h) = res.split_once('x').unwrap();
    let (w, h): (u16, u16) = (w.parse().unwrap(), h.parse().unwrap());
    let main = Stream::spawn(env("SPIKE_RTSP_MAIN_URL"), 8);
    let sub = Stream::spawn(env("SPIKE_RTSP_URL"), 8);
    for _ in 0..150 {
        if main.info().is_some() && sub.info().is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let (mi, si): (StreamInfo, StreamInfo) = (main.info().unwrap(), sub.info().unwrap());
    // With hwaccel = none (the one the harness uses) everything comes from the sub, including 1280x720.
    let raw_stream = &sub;

    // ffmpeg wrapped: its stderr goes to a file so we can count errors.
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("ffmpeg.log");
    let bin = dir.path().join("ffmpeg-wrap");
    std::fs::write(
        &bin,
        format!("#!/bin/sh\nexec ffmpeg \"$@\" 2>>{}\n", log.display()),
    )
    .unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let sessions = Sessions::new(
        main.clone(),
        sub.clone(),
        tiers_for(&mi, &si),
        HwAccel::None,
    )
    .with_bin(bin.to_string_lossy().into_owned());

    let vsock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let asock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut req = parse_request(include_bytes!(
        "../../../tests/fixtures/setup_endpoints.tlv"
    ))
    .unwrap();
    req.session_id = [5; 16];
    req.addr = "127.0.0.1".parse().unwrap();
    req.video_port = vsock.local_addr().unwrap().port();
    req.audio_port = asock.local_addr().unwrap().port();
    req.video_srtp = SrtpParams {
        key: KEY,
        salt: SALT,
    };
    req.audio_srtp = req.video_srtp.clone();
    let resp = sessions
        .prepare_with(req, "127.0.0.1".parse().unwrap())
        .unwrap();
    // Ports the accessory announced: packets must arrive FROM them.
    let adv = {
        let t = Tlv8::parse(&resp).unwrap();
        let a = Tlv8::parse(t.get(3).unwrap()).unwrap();
        (
            a.get_u16(3).unwrap().unwrap(),
            a.get_u16(4).unwrap().unwrap(),
        )
    };

    // Filler RR every 5 s to the announced port (without them the session expires after 30 s).
    tokio::spawn(async move {
        let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            let rr = [0x80, 201, 0, 1, 0, 0, 0, 1];
            let _ = s.send_to(&rr, ("127.0.0.1", adv.0));
            let _ = s.send_to(&rr, ("127.0.0.1", adv.1));
        }
    });
    let t0 = Instant::now();
    let end = t0 + Duration::from_secs(secs);
    // Raw capture (same retina connection the session uses).
    let raw = {
        let (_, mut vrx) = raw_stream.subscribe();
        let mut arx = raw_stream.subscribe_audio();
        tokio::spawn(async move {
            let mut r = Raw::default();
            // HARNESS_DUMP=path: saves the raw HEVC to test ffmpeg offline.
            let mut dump = std::env::var("HARNESS_DUMP")
                .ok()
                .and_then(|p| std::fs::File::create(p).ok());
            loop {
                tokio::select! {
                    _ = tokio::time::sleep_until(end) => break,
                    f = vrx.recv() => if let Ok(f) = f {
                        if let Some(d) = dump.as_mut() {
                            use std::io::Write;
                            let _ = d.write_all(&f.annexb);
                        }
                        r.video.push((t0.elapsed().as_millis(), f.pts90k, f.keyframe, hevc_nals(&f.annexb)));
                    },
                    a = arx.recv() => if let Ok(a) = a {
                        r.audio.push((t0.elapsed().as_millis(), a.pts, a.alaw.len()));
                    },
                }
            }
            r
        })
    };
    let keys = session_keys();
    let t0_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs_f64()
        * 1000.0;
    // (arrival ms since t0, ntp ms since t0, RTP ts) of each SR; [0]=video [1]=audio.
    let srs = std::sync::Arc::new(std::sync::Mutex::new([vec![], vec![]]));
    let (srv, sra) = (srs.clone(), srs.clone());
    let vtask = tokio::spawn(async move {
        let (mut buf, mut out) = ([0u8; 2000], (None, vec![], 0u32, 0u32, vec![]));
        let (mut au_bytes, mut sizes) = (0usize, vec![]);
        let mut first_au = true;
        let mut max_udp = 0usize;
        // HARNESS_H264=path: saves the depacketized H.264 (Annex B) for ffprobe.
        let mut dump = std::env::var("HARNESS_H264")
            .ok()
            .and_then(|p| std::fs::File::create(p).ok());
        let adv_v = adv.0;
        let mtu = 1378usize;
        let mut srcs = std::collections::BTreeMap::<(u16, u8), u32>::new();
        while let Ok(Ok((n, src))) = tokio::time::timeout_at(end, vsock.recv_from(&mut buf)).await {
            if n >= 2 {
                *srcs.entry((src.port(), buf[1] & 0x7f)).or_default() += 1;
            }
            if let Some((ntp, rts)) = unprotect_sr(&buf[..n]) {
                srv.lock().unwrap()[0].push((t0.elapsed().as_millis() as f64, ntp - t0_unix, rts));
            }
            if n < 24 || buf[0] >> 6 != 2 || buf[1] & 0x7f != 99 {
                continue;
            }
            max_udp = max_udp.max(n);
            let (marker, _, ts, pay) = unprotect(&buf[..n], &keys);
            if let Some(d) = dump.as_mut() {
                use std::io::Write;
                let sc = [0, 0, 0, 1];
                match pay[0] & 0x1f {
                    24 => {
                        let mut i = 1;
                        while i + 2 <= pay.len() {
                            let l = u16::from_be_bytes([pay[i], pay[i + 1]]) as usize;
                            let _ = d.write_all(&sc);
                            let _ = d.write_all(&pay[i + 2..(i + 2 + l).min(pay.len())]);
                            i += 2 + l;
                        }
                    }
                    28 => {
                        if pay[1] & 0x80 != 0 {
                            let _ = d.write_all(&sc);
                            let _ = d.write_all(&[(pay[0] & 0xe0) | (pay[1] & 0x1f)]);
                        }
                        let _ = d.write_all(&pay[2..]);
                    }
                    _ => {
                        let _ = d.write_all(&sc);
                        let _ = d.write_all(&pay);
                    }
                }
            }
            out.2 += 1;
            au_bytes += n;
            if out.0.is_none() {
                out.0 = Some(t0.elapsed().as_millis());
            }
            if first_au {
                out.1.extend(h264_nals(&pay));
                first_au = !marker;
            }
            out.3 += u32::from(marker);
            if marker {
                sizes.push(au_bytes);
                au_bytes = 0;
                out.4.push((t0.elapsed().as_millis(), ts));
            }
        }
        println!(
            "video: advertised port={adv_v}; (source port, PT) -> packets: {srcs:?}; all from the advertised one: {}",
            srcs.keys().all(|k| k.0 == adv_v)
        );
        println!(
            "video: UDP datagram max={max_udp} B (requested MTU {mtu}, usable UDP payload IPv4={} IPv6={})",
            mtu - 28,
            mtu - 48
        );
        sizes.sort();
        println!(
            "video: frame size (bytes) median={} p95={} max={}",
            sizes[sizes.len() / 2],
            sizes[sizes.len() * 95 / 100],
            sizes[sizes.len() - 1]
        );
        out
    });
    let atask = tokio::spawn(async move {
        let (mut buf, mut v) = ([0u8; 2000], vec![]);
        while let Ok(Ok((n, src))) = tokio::time::timeout_at(end, asock.recv_from(&mut buf)).await {
            if src.port() != adv.1 {
                println!(
                    "audio: packet from port {} != advertised {}",
                    src.port(),
                    adv.1
                );
            }
            if let Some((ntp, rts)) = unprotect_sr(&buf[..n]) {
                sra.lock().unwrap()[1].push((t0.elapsed().as_millis() as f64, ntp - t0_unix, rts));
            }
            if n > 12 && buf[0] >> 6 == 2 && buf[1] & 0x7f == 110 {
                let ts = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
                v.push((t0.elapsed().as_millis(), ts));
            }
        }
        v
    });

    let sel = SelectedConfig {
        session_id: [5; 16],
        video: VideoSel {
            width: w,
            height: h,
            fps: 25,
            profile: std::env::var("HARNESS_PROFILE").map_or(2, |s| s.parse().unwrap()),
            level: std::env::var("HARNESS_LEVEL").map_or(2, |s| s.parse().unwrap()),
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
    };
    assert_eq!(sessions.start_legacy(sel).await, Status::Success);
    let raw = raw.await.unwrap();
    let (first_v, first_nals, vpkts, vframes, vts) = vtask.await.unwrap();
    let a = atask.await.unwrap();
    let _ = sessions.end([5; 16]).await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    // (d) raw
    let kfs: Vec<_> = raw.video.iter().filter(|v| v.2).collect();
    println!("== RAW {res} (sub) ==");
    println!("frames={} keyframes={}", raw.video.len(), kfs.len());
    for k in kfs.iter().take(4) {
        println!("  keyframe t={}ms pts={} nals={:?}", k.0, k.1, k.3);
    }
    let non_idr_start = raw
        .video
        .iter()
        .take(40)
        .map(|v| (v.2, v.3.clone()))
        .collect::<Vec<_>>();
    println!(
        "  first 14 frames (key, nals): {:?}",
        &non_idr_start[..14.min(non_idr_start.len())]
    );
    let kt: Vec<u128> = kfs.iter().map(|k| k.0).collect();
    let near_kf = |t: u128| kt.iter().any(|k| t >= *k && t < *k + 500);
    let raw_big: Vec<_> = raw
        .audio
        .windows(2)
        .filter(|w| w[1].0 - w[0].0 > 100)
        .collect();
    println!(
        "  raw gaps >100ms: {} (within 500 ms after a keyframe: {})",
        raw_big.len(),
        raw_big.iter().filter(|w| near_kf(w[1].0)).count()
    );
    println!(
        "  keyframe interval ms: {:?}",
        kt.windows(2).map(|w| w[1] - w[0]).collect::<Vec<_>>()
    );
    let gaps: Vec<u128> = raw.audio.windows(2).map(|w| w[1].0 - w[0].0).collect();
    let big = gaps.iter().filter(|g| **g > 100).count();
    println!(
        "  raw audio: packets={} bytes/pkt={:?} max gap={}ms >100ms: {big}",
        raw.audio.len(),
        raw.audio.first().map(|a| a.2),
        gaps.iter().max().unwrap_or(&0)
    );
    let pts_bad = raw
        .audio
        .windows(2)
        .filter(|w| w[1].1 - w[0].1 != w[1].2 as i64)
        .count();
    println!("  audio pts discontinuities (delta != samples): {pts_bad}");
    for (i, w) in raw.audio.windows(2).enumerate() {
        if w[1].0 - w[0].0 > 100 && i < 100000 {
            println!("    raw gap {}ms at t={}ms", w[1].0 - w[0].0, w[1].0);
        }
    }
    // (a)(b)(c)
    let log = std::fs::read_to_string(&log).unwrap_or_default();
    let count = |p: &str| log.lines().filter(|l| l.contains(p)).count();
    println!("== PIPELINE ==");
    println!(
        "ffmpeg errors: POC={} RPS={} undecodable={} DTS_disc={} total_lines={}",
        count("Could not find ref"),
        count("Error constructing the frame RPS"),
        count("Skipping invalid undecodable"),
        count("DTS discontinuity"),
        log.lines().count()
    );
    println!(
        "video: first RTP at {:?} ms, packets={vpkts} frames(marker)={vframes}, first AU H.264 NALs={first_nals:?} idr={}",
        first_v,
        first_nals.contains(&5)
    );
    let vts_all = vts.clone();
    let vts: Vec<_> = vts.into_iter().filter(|x| x.0 > 3500).collect(); // without the startup (burst backlog)
    let vg: Vec<u128> = vts.windows(2).map(|w| w[1].0 - w[0].0).collect();
    let vtd: Vec<i64> = vts
        .windows(2)
        .map(|w| i64::from(w[1].1.wrapping_sub(w[0].1)) / 90)
        .collect();
    println!(
        "video frames (>3.5 s, of {}): arrival max gap={}ms >300ms={}; ts delta (ms) min={} max={}; ts-arrival drift={}ms",
        vts_all.len(),
        vg.iter().max().unwrap_or(&0),
        vg.iter().filter(|g| **g > 300).count(),
        vtd.iter().min().unwrap_or(&0),
        vtd.iter().max().unwrap_or(&0),
        match (vts.first(), vts.last()) {
            (Some(f), Some(l)) => i64::from(l.1.wrapping_sub(f.1)) / 90 - (l.0 - f.0) as i64,
            _ => 0,
        }
    );
    // Video timestamps around each keyframe (raw: arrival and pts; output: RTP ts).
    println!("== VIDEO TIMING ==");
    for w in raw.video.windows(2) {
        let (da, dp) = (w[1].0 - w[0].0, (w[1].1 - w[0].1) / 90);
        if w[1].2 || da > 200 || dp > 150 {
            println!(
                "  raw t={}ms key={} arrival +{da}ms pts +{dp}ms",
                w[1].0, w[1].2
            );
        }
    }
    let tsd: Vec<(u128, i64)> = vts_all
        .windows(2)
        .map(|w| (w[1].0, i64::from(w[1].1.wrapping_sub(w[0].1)) / 90))
        .collect();
    let jumps: Vec<_> = tsd.iter().filter(|d| d.1 > 150 || d.1 < 20).collect();
    println!(
        "output: RTP ts delta >150ms or <20ms: {} of {} (max={}ms); (t, delta)={:?}",
        jumps.len(),
        tsd.len(),
        tsd.iter().map(|d| d.1).max().unwrap_or(0),
        &jumps[..jumps.len().min(40)]
    );
    // A/V drift: how far each RTP clock strays from the wall clock (ts - arrival, between the
    // packet 10 and the last one); the difference is what the receiver sees as misalignment.
    let drift = |v: &[(u128, u32)], hz: i64| {
        let (f, l) = (v[10], v[v.len() - 1]);
        i64::from(l.1.wrapping_sub(f.1)) * 1000 / hz - (l.0 - f.0) as i64
    };
    if vts_all.len() > 12 && a.len() > 12 {
        let (dv, da) = (drift(&vts_all, 90_000), drift(&a, 48_000));
        println!(
            "drift vs wall clock: video {dv}ms audio {da}ms => A/V {}ms",
            dv - da
        );
    }
    // SR consistency: implied time of each RTP packet according to the last SR vs its
    // real arrival. The receiver aligns A/V with this; (video - audio) is the A/V offset it sees.
    let srs = srs.lock().unwrap();
    let err = |pk: &[(u128, u32)], sr: &[(f64, f64, u32)], hz: f64| -> Option<(f64, f64, f64)> {
        let e: Vec<f64> = pk
            .iter()
            .filter_map(|p| {
                let s = sr.iter().rev().find(|s| s.0 <= p.0 as f64)?;
                Some(p.0 as f64 - (s.1 + f64::from(p.1.wrapping_sub(s.2) as i32) / hz * 1000.0))
            })
            .collect();
        let m = e.iter().sum::<f64>() / e.len().max(1) as f64;
        (!e.is_empty()).then(|| {
            (
                m,
                e.iter().cloned().fold(f64::MAX, f64::min),
                e.iter().cloned().fold(f64::MIN, f64::max),
            )
        })
    };
    let (ev, ea) = (err(&vts_all, &srs[0], 90000.0), err(&a, &srs[1], 48000.0));
    println!(
        "SR: video n={} audio n={}; implied-arrival error (mean,min,max ms): video {ev:?} audio {ea:?}; mean A/V {:?} ms",
        srs[0].len(),
        srs[1].len(),
        ev.zip(ea).map(|(v, a)| v.0 - a.0)
    );
    let gaps: Vec<u128> = a.windows(2).map(|w| w[1].0 - w[0].0).collect();
    let steady: Vec<_> = a.iter().filter(|x| x.0 > 3000).collect();
    let sg: Vec<u128> = steady.windows(2).map(|w| w[1].0 - w[0].0).collect();
    let tsj = steady
        .windows(2)
        .filter(|w| w[1].1.wrapping_sub(w[0].1) != 960)
        .count();
    println!(
        "audio: packets={} first={:?}ms max gap(total)={}ms max gap(>3s)={}ms >100ms={} ts!=+960: {tsj}",
        a.len(),
        a.first().map(|x| x.0),
        gaps.iter().max().unwrap_or(&0),
        sg.iter().max().unwrap_or(&0),
        sg.iter().filter(|g| **g > 100).count()
    );
    let mut sg2 = sg.clone();
    sg2.sort_unstable();
    if !sg2.is_empty() {
        let mean = sg2.iter().sum::<u128>() as f64 / sg2.len() as f64;
        println!(
            "audio gaps >40ms: {} in {} s",
            sg2.iter().filter(|g| **g > 40).count(),
            sg2.iter().sum::<u128>() / 1000
        );
        println!(
            "audio inter-arrival (>3 s): mean={mean:.1}ms p50={} p95={} p99={} max={} (n={})",
            sg2[sg2.len() / 2],
            sg2[sg2.len() * 95 / 100],
            sg2[sg2.len() * 99 / 100],
            sg2[sg2.len() - 1],
            sg2.len()
        );
    }
    for (i, w) in a.windows(2).enumerate() {
        if w[1].0 - w[0].0 > 100 && i < 100000 {
            println!(
                "    RTP audio gap {}ms at t={}ms (ts delta {})",
                w[1].0 - w[0].0,
                w[1].0,
                w[1].1.wrapping_sub(w[0].1)
            );
        }
    }
    println!("--- first lines of the ffmpeg log ---");
    for l in log.lines().take(8) {
        println!("  {l}");
    }
}
