use std::collections::VecDeque;

use super::Frame;

/// Hard memory cap: a camera without keyframes must not let the ring grow without bound.
const MAX_BYTES: usize = 64 << 20;

/// Frame prebuffer that always starts at a keyframe and discards whole GOPs.
pub struct Ring {
    max_ticks: i64,
    max_bytes: usize,
    bytes: usize,
    frames: VecDeque<Frame>,
}

impl Ring {
    pub fn new(secs: u32) -> Ring {
        Ring::with_cap(secs, MAX_BYTES)
    }

    pub fn with_cap(secs: u32, max_bytes: usize) -> Ring {
        Ring {
            max_ticks: secs as i64 * 90_000,
            max_bytes,
            bytes: 0,
            frames: VecDeque::new(),
        }
    }

    fn pop_front(&mut self) {
        if let Some(f) = self.frames.pop_front() {
            self.bytes -= f.annexb.len();
        }
    }

    pub fn push(&mut self, f: Frame) {
        if self.frames.is_empty() && !f.keyframe {
            return; // the ring always starts at a keyframe
        }
        let now = f.pts90k;
        self.bytes += f.annexb.len();
        self.frames.push_back(f);
        // Discard the first GOP while the rest still covers `secs`.
        while let Some(second) = self.frames.iter().skip(1).find(|f| f.keyframe) {
            if now - second.pts90k < self.max_ticks {
                break;
            }
            let pts = second.pts90k;
            while self
                .frames
                .front()
                .is_some_and(|f| f.pts90k != pts || !f.keyframe)
            {
                self.pop_front();
            }
        }
        // Hard cap: evict even mid-GOP and discard up to the next keyframe.
        if self.bytes > self.max_bytes {
            while self.bytes > self.max_bytes {
                self.pop_front();
            }
            while self.frames.front().is_some_and(|f| !f.keyframe) {
                self.pop_front();
            }
        }
    }

    pub fn clear(&mut self) {
        self.frames.clear();
        self.bytes = 0;
    }

    #[allow(clippy::wrong_self_convention)] // name fixed by the contract
    pub fn from_last_keyframe(&self) -> Vec<Frame> {
        match self.frames.iter().rposition(|f| f.keyframe) {
            Some(i) => self.frames.iter().skip(i).cloned().collect(),
            None => vec![],
        }
    }

    /// From the last keyframe with pts <= `pts90k` (or the ring's first frame).
    pub fn since(&self, pts90k: i64) -> Vec<Frame> {
        let i = self
            .frames
            .iter()
            .rposition(|f| f.keyframe && f.pts90k <= pts90k)
            .unwrap_or(0);
        self.frames.iter().skip(i).cloned().collect()
    }

    /// pts of the ring's last frame.
    pub fn last_pts(&self) -> Option<i64> {
        self.frames.back().map(|f| f.pts90k)
    }

    pub fn latest_keyframe(&self) -> Option<Frame> {
        self.frames.iter().rev().find(|f| f.keyframe).cloned()
    }

    #[cfg(test)]
    fn span(&self) -> i64 {
        match (self.frames.front(), self.frames.back()) {
            (Some(a), Some(b)) => b.pts90k - a.pts90k,
            _ => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    /// 10 fps, 2 s GOP (20 frames), `secs` of video.
    fn fill(ring: &mut Ring, secs: i64) {
        for i in 0..secs * 10 {
            ring.push(Frame {
                pts90k: i * 9_000,
                keyframe: i % 20 == 0,
                annexb: Bytes::from_static(b"x"),
            });
        }
    }

    #[test]
    fn ring_keeps_whole_gops() {
        let mut r = Ring::new(8);
        fill(&mut r, 20);
        assert!(r.frames.front().unwrap().keyframe);
        let s = r.span();
        assert!((8 * 90_000..=10 * 90_000).contains(&s), "span {s}");
    }

    #[test]
    fn byte_cap_evicts_and_restarts_on_keyframe() {
        let mut r = Ring::with_cap(8, 100);
        for i in 0..50i64 {
            r.push(Frame {
                pts90k: i * 9_000,
                keyframe: i == 0 || i == 30, // huge GOP: the cap is reached mid-GOP
                annexb: Bytes::from(vec![0u8; 10]),
            });
            assert!(r.bytes <= 100, "bytes {}", r.bytes);
            assert!(r.frames.front().is_none_or(|f| f.keyframe));
            if i == 35 {
                assert!(r.latest_keyframe().is_some()); // after keyframe 30 it fills up again
            }
        }
    }

    #[test]
    fn from_last_keyframe_starts_with_keyframe() {
        let mut r = Ring::new(8);
        fill(&mut r, 15); // last keyframe at t=14 s
        let v = r.from_last_keyframe();
        assert!(v[0].keyframe);
        assert_eq!(v[0].pts90k, 14 * 90_000);
        assert_eq!(v.len(), 10);
    }

    #[test]
    fn last_pts_is_newest() {
        let mut r = Ring::new(8);
        assert_eq!(r.last_pts(), None);
        fill(&mut r, 3);
        assert_eq!(r.last_pts(), Some(29 * 9_000));
    }

    #[test]
    fn since_rounds_down_to_keyframe() {
        let mut r = Ring::new(8);
        fill(&mut r, 20);
        let v = r.since(15 * 90_000); // keyframes at 14 s and 16 s
        assert!(v[0].keyframe);
        assert_eq!(v[0].pts90k, 14 * 90_000);
    }
}
