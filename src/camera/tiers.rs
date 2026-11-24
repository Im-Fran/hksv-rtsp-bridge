//! Video tiers offered to Home: High (main, not transcoded), Medium (720p
//! transcoded) and Low (sub, not transcoded).

use crate::media::StreamInfo;

/// Video Quality value in Apple's guide (1 = Highest ... 4 = Low).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Quality {
    Highest = 1,
    High = 2,
    Medium = 3,
    Low = 4,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TierSource {
    MainCopy,
    SubCopy,
    MainTranscode,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tier {
    pub id: u32,
    pub quality: Quality,
    pub width: u16,
    pub height: u16,
    pub fps: u8,
    pub avg_kbps: u32,
    pub peak_kbps: u32,
    pub source: TierSource,
}

/// ponytail: 25 fixed until the Task 13 checkpoint (the sub measures ~12 fps, the guide asks for 24/30).
const FPS: u8 = 25;

/// Bitrates from the guide's table, based on the main stream's pixels.
fn guide_kbps(w: u16, h: u16) -> (u32, u32) {
    match w as u32 * h as u32 {
        p if p >= 3840 * 2160 => (4500, 5000),
        p if p >= 2560 * 1440 => (2800, 3000),
        p if p >= 1920 * 1080 => (1700, 1800),
        _ => (768, 800),
    }
}

pub fn tiers_for(main: &StreamInfo, sub: &StreamInfo) -> Vec<Tier> {
    let (avg, peak) = guide_kbps(main.width, main.height);
    let tier = |id, quality, width, height, avg_kbps, peak_kbps, source| Tier {
        id,
        quality,
        width,
        height,
        fps: FPS,
        avg_kbps,
        peak_kbps,
        source,
    };
    vec![
        tier(
            1,
            Quality::High,
            main.width,
            main.height,
            avg,
            peak,
            TierSource::MainCopy,
        ),
        // ponytail: Medium fixed at 1280x720 (assumes main is 16:9 and larger than 720p).
        tier(
            2,
            Quality::Medium,
            1280,
            720,
            768,
            800,
            TierSource::MainTranscode,
        ),
        tier(
            3,
            Quality::Low,
            sub.width,
            sub.height,
            180,
            190,
            TierSource::SubCopy,
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info(width: u16, height: u16) -> StreamInfo {
        StreamInfo {
            width,
            height,
            fps: 12.0,
            has_audio_alaw: true,
        }
    }

    #[test]
    fn tiers_for_icsee() {
        let t = tiers_for(&info(2560, 1440), &info(640, 360));
        let row = |t: &Tier| {
            (
                t.id,
                t.quality as u8,
                t.width,
                t.height,
                t.fps,
                t.avg_kbps,
                t.peak_kbps,
                t.source,
            )
        };
        assert_eq!(
            t.iter().map(row).collect::<Vec<_>>(),
            [
                (1, 2, 2560, 1440, 25, 2800, 3000, TierSource::MainCopy),
                (2, 3, 1280, 720, 25, 768, 800, TierSource::MainTranscode),
                (3, 4, 640, 360, 25, 180, 190, TierSource::SubCopy),
            ]
        );
    }
}
