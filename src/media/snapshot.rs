//! JPEG snapshots: the camera's HTTP URL if it exists; otherwise the last keyframe via ffmpeg.
//! Note: the keyframe comes from the 360p substream; requesting 1080p upscales it.
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};

use super::Codec;
use super::ffmpeg::Ffmpeg;
use super::ingest::Stream;
use crate::redact::redact;

const CACHE_TTL: Duration = Duration::from_secs(2);
const HTTP_TIMEOUT: Duration = Duration::from_secs(2);
const FFMPEG_TIMEOUT: Duration = Duration::from_secs(5);

/// `w`/`h` = 0: original size (unscaled), as go2rtc does when the request has no dimensions.
pub fn snapshot_args(codec: Codec, w: u32, h: u32) -> Vec<String> {
    let mut a: Vec<String> = ["-f", codec.ffmpeg_fmt(), "-i", "-", "-frames:v", "1"]
        .map(String::from)
        .to_vec();
    if w > 0 && h > 0 {
        a.extend(["-vf".into(), format!("scale={w}:{h}")]);
    }
    a.extend(
        [
            "-f", "image2", "-update", "1", "-c:v", "mjpeg", "-q:v", "5", "pipe:1",
        ]
        .map(String::from),
    );
    a
}

async fn encode_keyframe(codec: Codec, annexb: &[u8], w: u32, h: u32) -> Result<Vec<u8>> {
    let run = async {
        let mut f = Ffmpeg::spawn(snapshot_args(codec, w, h))?;
        f.write(annexb).await?;
        f.wait_output().await
    };
    // kill_on_drop kills ffmpeg if the timeout expires
    tokio::time::timeout(FFMPEG_TIMEOUT, run)
        .await
        .context("ffmpeg took more than 5 s")?
}

async fn fetch_url(url: &str) -> Result<Vec<u8>> {
    let r = reqwest::Client::builder()
        .timeout(HTTP_TIMEOUT)
        .build()?
        .get(url)
        .send()
        .await?
        .error_for_status()?;
    let ct_ok = r
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("image/jpeg"));
    let body = r.bytes().await?;
    anyhow::ensure!(
        ct_ok || body.starts_with(&[0xFF, 0xD8]),
        "response is not JPEG"
    );
    Ok(body.to_vec())
}

type Cache = HashMap<(u32, u32), (Instant, Vec<u8>)>;

/// Snapshots with a 2 s cache per (w, h).
pub struct Snapshotter {
    sub: Stream,
    url: Option<String>,
    cache: Mutex<Cache>,
}

impl Snapshotter {
    pub fn new(sub: Stream, url: Option<String>) -> Snapshotter {
        Snapshotter {
            sub,
            url,
            cache: Mutex::new(HashMap::new()),
        }
    }

    pub async fn get(&self, w: u32, h: u32) -> Result<Vec<u8>> {
        if let Some((t, b)) = self.cache.lock().unwrap().get(&(w, h))
            && t.elapsed() < CACHE_TTL
        {
            return Ok(b.clone());
        }
        let jpg = self.fresh(w, h).await?;
        self.cache
            .lock()
            .unwrap()
            .insert((w, h), (Instant::now(), jpg.clone()));
        Ok(jpg)
    }

    async fn fresh(&self, w: u32, h: u32) -> Result<Vec<u8>> {
        if let Some(url) = &self.url {
            match fetch_url(url).await {
                Ok(b) => return Ok(b),
                Err(e) => tracing::warn!(
                    "URL snapshot failed, using keyframe: {}",
                    redact(&format!("{e:#}"))
                ),
            }
        }
        let kf = self
            .sub
            .latest_keyframe()
            .context("no keyframe available")?;
        encode_keyframe(self.sub.codec(), &kf.annexb, w, h).await
    }
}

/// Shortcut without cache (original contract); use `Snapshotter` to cache.
pub async fn snapshot(sub: &Stream, url: Option<&str>, w: u32, h: u32) -> Result<Vec<u8>> {
    Snapshotter::new(sub.clone(), url.map(String::from))
        .fresh(w, h)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_args_has_scale_and_mjpeg() {
        let a = snapshot_args(Codec::H265, 640, 360).join(" ");
        assert!(a.contains("-f hevc"), "{a}");
        assert!(a.contains("scale=640:360"), "{a}");
        assert!(a.contains("mjpeg"), "{a}");
    }

    #[test]
    fn snapshot_args_without_dimensions_keep_original_size() {
        let a = snapshot_args(Codec::H265, 0, 0).join(" ");
        assert!(!a.contains("scale") && a.contains("mjpeg"), "{a}");
    }

    #[tokio::test]
    #[ignore = "requiere ffmpeg"]
    async fn snapshot_from_keyframe() {
        let kf = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/keyframe_360p.hevc"
        ))
        .unwrap();
        let jpg = encode_keyframe(Codec::H265, &kf, 640, 360).await.unwrap();
        assert_eq!(&jpg[..2], &[0xFF, 0xD8]);
        let big = encode_keyframe(Codec::H265, &kf, 1920, 1080).await.unwrap();
        assert_eq!(&big[..2], &[0xFF, 0xD8]);
    }
}
