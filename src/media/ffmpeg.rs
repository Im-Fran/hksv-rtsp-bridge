//! Minimal supervisor for ffmpeg subprocesses (stdin piped, stderr to tracing).
use std::collections::HashMap;
use std::process::Stdio;
use std::time::Duration;

use tokio::time::Instant;

use anyhow::{Context, Result};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, Command};

use crate::redact::redact;

/// Interval between notices for a repeated warning.
const DEDUP_EVERY: Duration = Duration::from_secs(10);
const DEDUP_MAX_KEYS: usize = 64;

/// Rate-limits identical ffmpeg warnings: the first is logged, then a summary with the
/// count every 10 s. "Identical" ignores numbers ("Could not find ref with POC 12").
#[derive(Default)]
struct LogDedup(HashMap<String, (u32, Instant, String)>);

impl LogDedup {
    fn offer(&mut self, line: &str, now: Instant) -> Option<String> {
        let key: String = line.chars().fold(String::new(), |mut k, c| {
            if !(c.is_ascii_digit() && k.ends_with('#')) {
                k.push(if c.is_ascii_digit() { '#' } else { c });
            }
            k
        });
        if self.0.len() >= DEDUP_MAX_KEYS && !self.0.contains_key(&key) {
            self.0.clear();
        }
        let Some((n, last, _)) = self.0.get_mut(&key) else {
            self.0.insert(key, (0, now, line.to_string()));
            return Some(line.to_string());
        };
        *n += 1;
        if now.duration_since(*last) < DEDUP_EVERY {
            return None;
        }
        let msg = format!(
            "{line} (repeated {n} times in the last {} s)",
            now.duration_since(*last).as_secs()
        );
        (*n, *last) = (0, now);
        Some(msg)
    }

    /// Summaries pending when the process ends.
    fn flush(&mut self) -> Vec<String> {
        self.0
            .drain()
            .filter(|(_, (n, ..))| *n > 0)
            .map(|(_, (n, _, l))| format!("{l} (repeated {n} more times)"))
            .collect()
    }
}

pub struct Ffmpeg {
    child: Child,
    stdin: Option<ChildStdin>,
}

impl Ffmpeg {
    /// `ffmpeg` binary from PATH (override with `HKSV_RTSP_BRIDGE_FFMPEG`). Kills the process on drop.
    pub fn spawn(args: Vec<String>) -> Result<Ffmpeg> {
        let bin = std::env::var("HKSV_RTSP_BRIDGE_FFMPEG").unwrap_or_else(|_| "ffmpeg".into());
        Self::spawn_bin(&bin, args)
    }

    pub fn spawn_bin(bin: &str, args: Vec<String>) -> Result<Ffmpeg> {
        let mut child = Command::new(bin)
            .args(["-hide_banner", "-loglevel", "warning"])
            .args(&args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .with_context(|| format!("could not launch {bin}"))?;
        let stdin = child.stdin.take();
        let stderr = child.stderr.take().context("no stderr")?;
        tokio::spawn(async move {
            let mut lines = BufReader::new(stderr).lines();
            let mut dedup = LogDedup::default();
            while let Ok(Some(l)) = lines.next_line().await {
                if let Some(m) = dedup.offer(&redact(&l), Instant::now()) {
                    tracing::warn!("ffmpeg: {m}");
                }
            }
            for m in dedup.flush() {
                tracing::warn!("ffmpeg: {m}");
            }
        });
        Ok(Ffmpeg { child, stdin })
    }

    pub fn take_stdin(&mut self) -> Option<ChildStdin> {
        self.stdin.take()
    }

    pub fn take_stdout(&mut self) -> Option<tokio::process::ChildStdout> {
        self.child.stdout.take()
    }

    pub fn pid(&self) -> Option<u32> {
        self.child.id()
    }

    /// Waits for the process to exit.
    pub async fn wait(&mut self) {
        let _ = self.child.wait().await;
    }

    pub async fn write(&mut self, b: &[u8]) -> Result<()> {
        self.stdin
            .as_mut()
            .context("stdin closed")?
            .write_all(b)
            .await
            .context("writing to ffmpeg")
    }

    /// Closes stdin and returns all of stdout; error if ffmpeg exits with code != 0.
    pub async fn wait_output(mut self) -> Result<Vec<u8>> {
        drop(self.stdin.take());
        let mut out = self.child.stdout.take().context("no stdout")?;
        let mut buf = vec![];
        // reading stdout and waiting in parallel avoids a deadlock if ffmpeg fills the pipe
        let (r, st) = tokio::join!(out.read_to_end(&mut buf), self.child.wait());
        r?;
        anyhow::ensure!(st?.success(), "ffmpeg exited with error");
        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedup_logs_first_then_summary_every_10s() {
        let t0 = Instant::now();
        let mut d = LogDedup::default();
        let line = |n: u32| format!("Could not find ref with POC {n}");
        assert_eq!(d.offer(&line(1), t0).unwrap(), line(1));
        for n in 2..=130 {
            assert!(d.offer(&line(n), t0 + Duration::from_secs(1)).is_none());
        }
        // A different warning is still shown.
        assert!(d.offer("something else", t0).is_some());
        let m = d.offer(&line(131), t0 + Duration::from_secs(11)).unwrap();
        assert!(m.contains("repeated 130 times"), "{m}");
        assert!(d.offer(&line(132), t0 + Duration::from_secs(12)).is_none());
        assert_eq!(d.flush().len(), 1);
    }

    #[tokio::test]
    #[ignore = "requiere ffmpeg"]
    async fn ffmpeg_killed_on_drop() {
        let f = Ffmpeg::spawn(
            ["-f", "lavfi", "-i", "nullsrc", "-f", "null", "-"]
                .map(String::from)
                .to_vec(),
        )
        .unwrap();
        let pid = f.pid().unwrap() as i32;
        drop(f);
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        // kill(pid, 0) fails with ESRCH if the process no longer exists
        let alive = std::process::Command::new("kill")
            .args(["-0", &pid.to_string()])
            .status()
            .unwrap()
            .success();
        assert!(!alive);
    }
}
