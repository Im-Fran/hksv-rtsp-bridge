//! Persistent RTSP ingest and in-memory prebuffer.
pub mod ffmpeg;
pub mod ingest;
pub mod ring;
pub mod snapshot;

use bytes::Bytes;

/// Video codec of an RTSP stream. Cameras differ (some send H.264, others H.265).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Codec {
    H264,
    #[default]
    H265,
}

impl Codec {
    /// ffmpeg raw Annex B demuxer name (`-f <name>`).
    pub fn ffmpeg_fmt(self) -> &'static str {
        match self {
            Codec::H264 => "h264",
            Codec::H265 => "hevc",
        }
    }

    /// Does this Annex B access unit carry an IDR slice?
    pub fn has_idr(self, annexb: &[u8]) -> bool {
        annexb.windows(4).any(|w| {
            w[..3] == [0, 0, 1]
                && match self {
                    Codec::H264 => w[3] & 0x1f == 5,
                    Codec::H265 => matches!((w[3] >> 1) & 0x3f, 19 | 20),
                }
        })
    }
}

/// One access unit in Annex B. `pts90k` resets on each RTSP session.
#[derive(Clone, Debug)]
pub struct Frame {
    pub pts90k: i64,
    pub keyframe: bool,
    /// NAL units with start codes; keyframes are preceded by VPS/SPS/PPS.
    pub annexb: Bytes,
}

#[derive(Clone, Debug, PartialEq)]
pub struct StreamInfo {
    pub width: u16,
    pub height: u16,
    pub fps: f32,
    pub has_audio_alaw: bool,
}

/// G.711 A-law, 8 kHz mono.
#[derive(Clone, Debug)]
pub struct AudioPacket {
    pub pts: i64,
    pub alaw: Bytes,
}
