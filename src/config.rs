use std::collections::HashSet;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::Deserialize;

#[derive(Debug, Deserialize, Default, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum HwAccel {
    #[default]
    None,
    Vaapi,
}

/// Maximum resolution advertised in the classic H.264 service (114).
#[derive(Debug, Deserialize, Default, Clone, Copy, PartialEq, Eq)]
pub enum MaxResolution {
    #[default]
    #[serde(rename = "720p")]
    P720,
    #[serde(rename = "360p")]
    P360,
}

/// Classic H.264 service (Camera RTP Stream Management, 110) for controllers without iOS 27.
#[derive(Debug, Deserialize, Default, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Legacy {
    /// On the same accessory, alongside the HSV3 services.
    #[default]
    Same,
    /// Second accessory `<name> (H.264)` per camera, with its own identity.
    Separate,
    Off,
}

#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub server: Server,
    pub camera: Vec<Camera>,
}

#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Server {
    pub setup_code: String,
    pub state_dir: PathBuf,
    #[serde(default = "default_bind")]
    pub bind: IpAddr,
    #[serde(default = "default_base_port")]
    pub base_port: u16,
    #[serde(default)]
    pub hwaccel: HwAccel,
    #[serde(default = "default_prebuffer_secs")]
    pub prebuffer_secs: u32,
    /// Seconds that MotionDetected stays true after the camera's LAST alarm.
    #[serde(default = "default_motion_hold_secs")]
    pub motion_hold_secs: u32,
    /// Also publishes the iOS 27 HSV3/H.265 services (Multi-Tier RTP, WebRTC...). By default
    /// only the classic H.264 services, which is what works remotely today.
    #[serde(default)]
    pub hsv3: bool,
    /// Only applies with `hsv3 = true`.
    #[serde(default)]
    pub legacy: Legacy,
    /// Maximum resolution the classic service advertises (`"720p"` or `"360p"`).
    #[serde(default)]
    pub max_resolution: MaxResolution,
}

/// With `legacy = "separate"` the H.264 accessory of camera `i` uses port `base_port + 100 + i`.
pub const LEGACY_PORT_OFFSET: u16 = 100;

#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Camera {
    pub name: String,
    pub main: String,
    pub sub: String,
    pub motion: Option<String>,
    pub snapshot: Option<String>,
}

/// `::` is dual-stack (accepts IPv4 and IPv6); on Linux it is, unless `net.ipv6.bindv6only=1`.
/// This is needed because mDNS also advertises IPv6 addresses.
fn default_bind() -> IpAddr {
    IpAddr::from([0u16; 8])
}

fn default_base_port() -> u16 {
    51830
}

fn default_motion_hold_secs() -> u32 {
    10
}

fn default_prebuffer_secs() -> u32 {
    8
}

pub fn load(path: &Path) -> Result<Config> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading config {}", path.display()))?;
    parse(&text)
}

fn parse(text: &str) -> Result<Config> {
    let cfg: Config = toml::from_str(text).context("invalid TOML config")?;
    validate_setup_code(&cfg.server.setup_code)?;
    if cfg.camera.is_empty() {
        bail!("at least one camera is required");
    }
    if cfg.server.base_port as u32 + cfg.camera.len() as u32 > 65535 {
        bail!("base_port + number of cameras exceeds 65535");
    }
    let separate = cfg.server.hsv3 && cfg.server.legacy == Legacy::Separate;
    if separate
        && cfg.server.base_port as u32 + LEGACY_PORT_OFFSET as u32 + cfg.camera.len() as u32 > 65535
    {
        bail!("base_port + 100 + number of cameras exceeds 65535 (legacy = \"separate\")");
    }
    if separate && cfg.camera.len() > LEGACY_PORT_OFFSET as usize {
        bail!("legacy = \"separate\" supports at most 100 cameras");
    }
    let mut names = HashSet::new();
    for cam in &cfg.camera {
        if cam.name.trim().is_empty() {
            bail!("empty camera name");
        }
        if !names.insert(cam.name.as_str()) {
            bail!("duplicate camera name: {}", cam.name);
        }
    }
    Ok(cfg)
}

/// Format `DDD-DD-DDD`; rejects codes that HAP does not accept.
fn validate_setup_code(code: &str) -> Result<()> {
    let b = code.as_bytes();
    let shape_ok = b.len() == 10
        && b.iter().enumerate().all(|(i, c)| match i {
            3 | 6 => *c == b'-',
            _ => c.is_ascii_digit(),
        });
    if !shape_ok {
        bail!("setup_code must have the format DDD-DD-DDD");
    }
    let digits: String = code.chars().filter(|c| *c != '-').collect();
    let all_same = digits.bytes().all(|c| c == digits.as_bytes()[0]);
    if all_same || digits == "12345678" || digits == "87654321" {
        bail!("setup_code {code} is not valid for HomeKit");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/config.example.toml");

    fn with_setup_code(code: &str) -> String {
        format!(
            r#"
[server]
setup_code = "{code}"
state_dir = "/tmp/state"

[[camera]]
name = "Patio"
main = "rtsp://h/main"
sub = "rtsp://h/sub"
"#
        )
    }

    #[test]
    fn load_example_config() {
        let cfg = load(Path::new(EXAMPLE)).expect("config.example.toml must parse");
        assert_eq!(cfg.camera.len(), 1);
        assert_eq!(cfg.server.base_port, 51830);
        assert_eq!(cfg.server.hwaccel, HwAccel::None);
    }

    #[test]
    fn applies_server_defaults() {
        let cfg = parse(&with_setup_code("031-45-154")).unwrap();
        assert_eq!(cfg.server.bind, IpAddr::from([0u16; 8]));
        assert_eq!(cfg.server.base_port, 51830);
        assert_eq!(cfg.server.hwaccel, HwAccel::None);
        assert_eq!(cfg.server.prebuffer_secs, 8);
        assert_eq!(cfg.server.motion_hold_secs, 10);
        assert_eq!(cfg.server.legacy, Legacy::Same);
        assert!(!cfg.server.hsv3, "HSV3 disabled by default");
        assert_eq!(cfg.server.max_resolution, MaxResolution::P720);
        assert_eq!(cfg.camera[0].motion, None);
    }

    #[test]
    fn rejects_bad_setup_code() {
        for code in [
            "12345678",
            "111-11-111",
            "123-45-678",
            "876-54-321",
            "03a-45-154",
        ] {
            assert!(
                parse(&with_setup_code(code)).is_err(),
                "should have rejected setup_code {code}"
            );
        }
    }

    #[test]
    fn rejects_duplicate_camera_names() {
        let text = format!(
            "{}\n[[camera]]\nname = \"Patio\"\nmain = \"rtsp://h/m2\"\nsub = \"rtsp://h/s2\"\n",
            with_setup_code("031-45-154")
        );
        assert!(parse(&text).is_err());
    }

    #[test]
    fn rejects_unknown_fields() {
        let t = with_setup_code("031-45-154");
        assert!(parse(&t.replace("state_dir", "bogus = 1\nstate_dir")).is_err());
        assert!(
            parse(&format!(
                "{t}\n[[camera]]\nname=\"B\"\nmain=\"a\"\nsub=\"b\"\nextra=1\n"
            ))
            .is_err()
        );
        assert!(parse(&format!("bogus = 1\n{t}")).is_err());
    }

    #[test]
    fn rejects_empty_camera_list_and_empty_name() {
        let server = "[server]\nsetup_code = \"031-45-154\"\nstate_dir = \"/tmp/s\"\n";
        assert!(parse(server).is_err());
        let t = with_setup_code("031-45-154").replace("name = \"Patio\"", "name = \"  \"");
        assert!(parse(&t).is_err());
    }

    #[test]
    fn rejects_port_overflow() {
        let t = with_setup_code("031-45-154").replace("state_dir", "base_port = 65535\nstate_dir");
        assert!(parse(&t).is_err());
        let t = with_setup_code("031-45-154").replace("state_dir", "base_port = 65534\nstate_dir");
        assert!(parse(&t).is_ok());
    }

    #[test]
    fn hsv3_flag_parses() {
        let t = with_setup_code("031-45-154").replace("state_dir", "hsv3 = true\nstate_dir");
        assert!(parse(&t).unwrap().server.hsv3);
        let t = with_setup_code("031-45-154").replace("state_dir", "hsv3 = 1\nstate_dir");
        assert!(parse(&t).is_err());
    }

    #[test]
    fn max_resolution_parses() {
        for (v, want) in [("720p", MaxResolution::P720), ("360p", MaxResolution::P360)] {
            let t = with_setup_code("031-45-154")
                .replace("state_dir", &format!("max_resolution = \"{v}\"\nstate_dir"));
            assert_eq!(parse(&t).unwrap().server.max_resolution, want);
        }
        let t = with_setup_code("031-45-154")
            .replace("state_dir", "max_resolution = \"1080p\"\nstate_dir");
        assert!(parse(&t).is_err());
    }

    #[test]
    fn legacy_modes_parse_and_reject_unknown() {
        for (v, want) in [
            ("same", Legacy::Same),
            ("separate", Legacy::Separate),
            ("off", Legacy::Off),
        ] {
            let t = with_setup_code("031-45-154")
                .replace("state_dir", &format!("legacy = \"{v}\"\nstate_dir"));
            assert_eq!(parse(&t).unwrap().server.legacy, want);
        }
        let t = with_setup_code("031-45-154").replace("state_dir", "legacy = \"x\"\nstate_dir");
        assert!(parse(&t).is_err());
    }
}
