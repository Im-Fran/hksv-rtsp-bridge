//! Persistent RTSP ingest and in-memory prebuffer.
pub mod ffmpeg;
pub mod ingest;
pub mod ring;
pub mod snapshot;

use bytes::Bytes;

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
