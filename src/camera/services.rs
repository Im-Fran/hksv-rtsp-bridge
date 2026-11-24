//! HAP services for the camera (HKSV 17.99 guide) and their TLV8 values.
//!
//! The TLV8 lists in the guide separate their items with a TLV of type 0 and length 0 (not the 0xFF of
//! pairing). TLV8 values travel in the model as base64 strings.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use serde_json::{Value, json};
use uuid::Uuid;

use super::legacy;
use super::tiers::Tier;
use crate::config;
use crate::hap::model::{Accessory, Characteristic, Format, Perms, Service};
use crate::hap::tlv8::Tlv8;
use crate::hap::uuids as u;

pub const VIDEO_PT: u8 = 99;
pub const AUDIO_PT: u8 = 110;
const CODEC_H265: u8 = 2;
const CODEC_OPUS: u8 = 3;
/// Audio Sample Rate from the guide: 4 = 48 kHz (the guide and the reference implementations
/// report 48 kHz with Opus even when captured at 16 kHz; the brief said 1 = 16 kHz).
const AUDIO_RATE_48K: u8 = 4;

pub fn b64(b: &[u8]) -> Value {
    Value::String(B64.encode(b))
}

fn u16le(v: u16) -> [u8; 2] {
    v.to_le_bytes()
}

/// TLV8 list: each item has the same type, and they are separated by the empty type-0 TLV.
fn list(tag: u8, items: Vec<Vec<u8>>) -> Tlv8 {
    let mut t = Tlv8::new();
    for (i, it) in items.iter().enumerate() {
        if i > 0 {
            t = t.push(0, &[]);
        }
        t = t.push(tag, it);
    }
    t
}

fn concat(a: Tlv8, b: Tlv8) -> Vec<u8> {
    [a.encode(), b.encode()].concat()
}

/// Supported Video Stream Tiers (8043): H.265, PT 99, one TLV per tier.
pub fn video_tiers_tlv(tiers: &[Tier]) -> Vec<u8> {
    let items = tiers
        .iter()
        .map(|t| {
            Tlv8::new()
                .push_u32(1, t.id)
                .push_u8(2, t.quality as u8)
                .push_u32(3, t.avg_kbps)
                .push(4, &u16le(t.width))
                .push(5, &u16le(t.height))
                .push_u8(6, t.fps)
                .encode()
        })
        .collect();
    concat(
        Tlv8::new().push_u8(1, CODEC_H265).push_u8(2, VIDEO_PT),
        list(3, items),
    )
}

/// Supported Audio Stream Tiers (8044): one Opus tier, 24 kbps, 48 kHz, 16 bit, 20 ms, mono.
pub fn audio_tiers_tlv() -> Vec<u8> {
    let tier = Tlv8::new()
        .push_u32(1, 1)
        .push_u32(2, 24_000)
        .push_u8(3, AUDIO_RATE_48K)
        .push_u8(4, 2)
        .push_u8(5, 20)
        .push_u8(6, 1)
        .encode();
    concat(
        Tlv8::new().push_u8(1, CODEC_OPUS).push_u8(2, AUDIO_PT),
        list(3, vec![tier]),
    )
}

/// Supported RTP Configuration (116): AES_CM_128_HMAC_SHA1_80 only.
pub fn rtp_config_tlv() -> Vec<u8> {
    Tlv8::new().push_u8(2, 0).encode()
}

/// Camera Capabilities (8011): one sensor (dimensions of the largest tier) with one encoding
/// per tier. Each encoding's id is a stable UUID v5 derived from the sensor and the tier.
pub fn capabilities_tlv(sensor: Uuid, tiers: &[Tier]) -> Vec<u8> {
    let (w, h) = tiers.first().map_or((0, 0), |t| (t.width, t.height));
    let dims = Tlv8::new().push(1, &u16le(w)).push(2, &u16le(h)).encode();
    let streams = tiers
        .iter()
        .map(|t| {
            let id = Uuid::new_v5(&sensor, &t.id.to_le_bytes());
            Tlv8::new()
                .push(1, id.as_bytes())
                .push_u8(2, t.quality as u8)
                .push(3, &u16le(t.width))
                .push(4, &u16le(t.height))
                .push_u8(5, t.fps)
                .push_u32(6, t.avg_kbps)
                .push_u32(7, t.peak_kbps)
                .encode()
        })
        .collect();
    // sensor_type 1 = primary, intent 1 = main.
    let sensor_tlv = concat(
        Tlv8::new()
            .push(1, &dims)
            .push(2, sensor.as_bytes())
            .push_u8(3, 1)
            .push_u8(4, 1),
        list(5, streams),
    );
    let sensors = list(1, vec![sensor_tlv]).encode();
    Tlv8::new().push_u8(1, 1).push(2, &sensors).encode()
}

/// Camera Zones with no zones (version 2).
fn empty_zones_tlv() -> Vec<u8> {
    Tlv8::new().push_u8(1, 2).encode()
}

struct Builder {
    next: u64,
    services: Vec<Service>,
}

type Spec = (Uuid, Format, Perms, Value);

impl Builder {
    fn service(&mut self, ty: Uuid, primary: bool, chars: Vec<Spec>) {
        let iid = self.next;
        self.next += 1;
        let chars = chars
            .into_iter()
            .map(|(ty, format, perms, value)| {
                let iid = self.next;
                self.next += 1;
                Characteristic {
                    iid,
                    ty,
                    format,
                    perms,
                    value,
                }
            })
            .collect();
        self.services.push(Service {
            iid,
            ty,
            primary,
            hidden: false,
            linked: Vec::new(),
            chars,
        });
    }
}

const PR: Perms = Perms::PR;
/// Paired read/write + notify + timed write (RW in the guide).
fn rw() -> Perms {
    Perms::PR | Perms::PW | Perms::EV | Perms::TW
}

/// RW + AdminOnly (Streaming Enabled and Motion Enabled per the guide).
fn rw_admin() -> Perms {
    rw() | Perms::AA
}

/// Control TLV8 characteristic: read, write and write-response.
fn ctl() -> Perms {
    Perms::PR | Perms::PW | Perms::WR
}

fn accessory_information(b: &mut Builder, name: &str, device_id: &str) {
    let s = |v: &str| json!(v);
    b.service(
        u::ACCESSORY_INFORMATION,
        false,
        vec![
            (u::IDENTIFY, Format::Bool, Perms::PW, Value::Null),
            (u::MANUFACTURER, Format::String, PR, s("local-dvr")),
            (u::MODEL, Format::String, PR, s("RTSP Camera Bridge")),
            (u::NAME, Format::String, PR, s(name)),
            (u::SERIAL_NUMBER, Format::String, PR, s(device_id)),
            (
                u::FIRMWARE_REVISION,
                Format::String,
                PR,
                s(env!("CARGO_PKG_VERSION")),
            ),
        ],
    );
}

fn motion_sensor(b: &mut Builder, name: &str) {
    b.service(
        u::MOTION_SENSOR,
        false,
        vec![
            (
                u::MOTION_DETECTED,
                Format::Bool,
                PR | Perms::EV,
                json!(false),
            ),
            (u::NAME, Format::String, PR, json!(name)),
            (u::MOTION_ENABLED, Format::Bool, rw_admin(), json!(true)),
        ],
    );
}

fn hap_protocol_information(b: &mut Builder) {
    b.service(
        u::HAP_PROTOCOL_INFORMATION,
        false,
        vec![(u::VERSION, Format::String, PR, json!("1.1.0"))],
    );
}

/// Camera RTP Stream Management (110) + Microphone (112), same as go2rtc
/// (pkg/hap/camera/accessory.go): 120/114/115/116/B0/117/118, with 117 and 118 empty.
fn legacy_services(b: &mut Builder, max: config::MaxResolution) {
    b.service(
        u::CAMERA_RTP_STREAM_MANAGEMENT,
        false,
        vec![
            (
                u::STREAMING_STATUS,
                Format::Tlv8,
                PR | Perms::EV,
                b64(&legacy::streaming_status_tlv(0)),
            ),
            (
                u::SUPPORTED_VIDEO_STREAM_CONFIG,
                Format::Tlv8,
                PR,
                b64(&legacy::supported_video_tlv(max)),
            ),
            (
                u::SUPPORTED_AUDIO_STREAM_CONFIG,
                Format::Tlv8,
                PR,
                b64(&legacy::supported_audio_tlv()),
            ),
            (
                u::SUPPORTED_RTP_CONFIG,
                Format::Tlv8,
                PR,
                b64(&rtp_config_tlv()),
            ),
            (u::ACTIVE, Format::U8, PR | Perms::PW | Perms::EV, json!(1)),
            (
                u::SELECTED_RTP_STREAM_CONFIG,
                Format::Tlv8,
                PR | Perms::PW,
                b64(&[]),
            ),
            (u::SETUP_ENDPOINTS, Format::Tlv8, PR | Perms::PW, b64(&[])),
        ],
    );
    b.service(
        u::MICROPHONE,
        false,
        vec![(
            u::MUTE,
            Format::Bool,
            PR | Perms::PW | Perms::EV,
            json!(false),
        )],
    );
}

/// Accessory with classic services only (hsv3 = false, or `legacy = "separate"`): Accessory
/// Information + HAP Protocol Information (A2) + 110 + 112 + Motion Sensor (85).
pub fn build_classic_accessory(
    name: &str,
    device_id: &str,
    max: config::MaxResolution,
) -> Accessory {
    let mut b = Builder {
        next: 1,
        services: Vec::new(),
    };
    accessory_information(&mut b, name, device_id);
    hap_protocol_information(&mut b);
    legacy_services(&mut b, max);
    motion_sensor(&mut b, name);
    data_stream_transport(&mut b);
    recording_services(&mut b);
    Accessory {
        aid: 1,
        services: b.services,
    }
}

/// Classic HKSV, like HAP-NodeJS's `CameraController`: Camera Recording Management (204) linked
/// to Data Stream Transport Management (129) and the Motion Sensor (85), and Camera Operating Mode (21A).
/// Added at the end: the earlier iids do not change.
fn recording_services(b: &mut Builder) {
    use super::recording as rec;
    b.service(
        u::CAMERA_EVENT_RECORDING_MANAGEMENT,
        false,
        vec![
            (u::ACTIVE, Format::U8, rw(), json!(0)),
            (
                u::SUPPORTED_CAMERA_RECORDING_CONFIG,
                Format::Tlv8,
                PR | Perms::EV,
                b64(&rec::supported_camera_tlv()),
            ),
            (
                u::SUPPORTED_VIDEO_RECORDING_CONFIG,
                Format::Tlv8,
                PR | Perms::EV,
                b64(&rec::supported_video_tlv()),
            ),
            (
                u::SUPPORTED_AUDIO_RECORDING_CONFIG,
                Format::Tlv8,
                PR | Perms::EV,
                b64(&rec::supported_audio_tlv()),
            ),
            (
                u::SELECTED_CAMERA_RECORDING_CONFIG,
                Format::Tlv8,
                PR | Perms::PW | Perms::EV,
                b64(&[]),
            ),
            (u::RECORDING_AUDIO_ACTIVE, Format::U8, rw(), json!(0)),
        ],
    );
    b.service(
        u::CAMERA_OPERATING_MODE,
        false,
        vec![
            (u::EVENT_SNAPSHOTS_ACTIVE, Format::U8, rw(), json!(1)),
            (u::HOMEKIT_CAMERA_ACTIVE, Format::U8, rw(), json!(1)),
            (u::PERIODIC_SNAPSHOTS_ACTIVE, Format::U8, rw(), json!(1)),
            (
                u::CAMERA_OPERATING_MODE_INDICATOR,
                Format::U8,
                rw(),
                json!(1),
            ),
        ],
    );
    let iid_of = |b: &Builder, ty: Uuid| b.services.iter().find(|s| s.ty == ty).map(|s| s.iid);
    let links: Vec<u64> = [u::DATA_STREAM_TRANSPORT_MANAGEMENT, u::MOTION_SENSOR]
        .into_iter()
        .filter_map(|t| iid_of(b, t))
        .collect();
    if let Some(s) = b
        .services
        .iter_mut()
        .find(|s| s.ty == u::CAMERA_EVENT_RECORDING_MANAGEMENT)
    {
        s.linked = links;
    }
}

/// Data Stream Transport Management (129): 130 (TCP) + 131 (setup, write-response) + version.
fn data_stream_transport(b: &mut Builder) {
    b.service(
        u::DATA_STREAM_TRANSPORT_MANAGEMENT,
        false,
        vec![
            (
                u::SUPPORTED_DATA_STREAM_TRANSPORT_CONFIG,
                Format::Tlv8,
                PR,
                b64(&crate::hds::supported_config_tlv()),
            ),
            (
                u::SETUP_DATA_STREAM_TRANSPORT,
                Format::Tlv8,
                ctl(),
                b64(&[]),
            ),
            (u::VERSION, Format::String, PR, json!("1.0")),
        ],
    );
}

/// `legacy`: also adds the classic H.264 service (`legacy = "same"`).
pub fn build_accessory(
    cam: &config::Camera,
    device_id: &str,
    tiers: &[Tier],
    sensor_uuid: Uuid,
    legacy: bool,
    max: config::MaxResolution,
) -> Accessory {
    let mut b = Builder {
        next: 1,
        services: Vec::new(),
    };
    let s = |v: &str| json!(v);
    accessory_information(&mut b, &cam.name, device_id);
    hap_protocol_information(&mut b);
    b.service(
        u::CAMERA_CAPABILITIES,
        false,
        vec![
            (u::VERSION, Format::String, PR, s("17.99")),
            (
                u::CAMERA_CAPABILITIES_CHAR,
                Format::Tlv8,
                PR,
                b64(&capabilities_tlv(sensor_uuid, tiers)),
            ),
        ],
    );
    b.service(
        u::GLOBAL_OPERATING_MODE,
        false,
        vec![
            (u::HOMEKIT_CAMERA_ACTIVE, Format::U8, rw(), json!(1)),
            (u::STREAMING_ENABLED, Format::Bool, rw_admin(), json!(true)),
            (
                u::CAMERA_OPERATING_MODE_INDICATOR,
                Format::Bool,
                rw(),
                json!(true),
            ),
        ],
    );
    motion_sensor(&mut b, &cam.name);
    b.service(
        u::MOTION_ZONES,
        false,
        vec![
            (u::VERSION, Format::String, PR, s("17.99")),
            (u::ACTIVE, Format::U8, PR | Perms::PW | Perms::EV, json!(1)),
            (
                u::CAMERA_ZONES,
                Format::Tlv8,
                PR | Perms::PW,
                b64(&empty_zones_tlv()),
            ),
        ],
    );
    b.service(
        u::MULTI_TIER_RTP,
        true,
        vec![
            (u::STREAMING_ENABLED, Format::Bool, rw_admin(), json!(true)),
            (u::STATUS_ACTIVE, Format::Bool, PR | Perms::EV, json!(true)),
            (
                u::SUPPORTED_VIDEO_STREAM_TIERS,
                Format::Tlv8,
                PR | Perms::EV,
                b64(&video_tiers_tlv(tiers)),
            ),
            (
                u::SUPPORTED_AUDIO_STREAM_TIERS,
                Format::Tlv8,
                PR | Perms::EV,
                b64(&audio_tiers_tlv()),
            ),
            (
                u::SUPPORTED_RTP_CONFIG,
                Format::Tlv8,
                PR,
                b64(&rtp_config_tlv()),
            ),
            (u::SETUP_ENDPOINTS, Format::Tlv8, PR | Perms::PW, b64(&[])),
            (u::RTP_STREAMING_CONTROL, Format::Tlv8, ctl(), b64(&[])),
            (
                u::SENSOR_UUID,
                Format::Data,
                PR,
                b64(sensor_uuid.as_bytes()),
            ),
        ],
    );
    b.service(
        u::WEBRTC,
        false,
        vec![
            (u::WEBRTC_SOLICIT_OFFER, Format::Tlv8, ctl(), b64(&[])),
            (u::WEBRTC_PROVIDE_ANSWER, Format::Tlv8, ctl(), b64(&[])),
            (u::WEBRTC_STREAMING_CONTROL, Format::Tlv8, ctl(), b64(&[])),
            (
                u::NUMBER_OF_ACTIVE_SESSIONS,
                Format::U8,
                PR | Perms::EV,
                json!(0),
            ),
            (u::WEBRTC_REOFFER, Format::Tlv8, ctl(), b64(&[])),
            (u::WEBRTC_UPDATE_SESSION, Format::Tlv8, ctl(), b64(&[])),
            (
                u::WEBRTC_SUPPORTED_VIDEO_TIERS,
                Format::Tlv8,
                PR | Perms::EV,
                b64(&video_tiers_tlv(tiers)),
            ),
            (
                u::WEBRTC_SUPPORTED_AUDIO_TIERS,
                Format::Tlv8,
                PR | Perms::EV,
                b64(&audio_tiers_tlv()),
            ),
            (u::STREAMING_ENABLED, Format::Bool, rw_admin(), json!(true)),
            (
                u::SENSOR_UUID,
                Format::Data,
                PR,
                b64(sensor_uuid.as_bytes()),
            ),
        ],
    );
    // Declared without logic: Recording Management (stage 6) and Buffer Management (stage 7).
    b.service(
        u::CAMERA_EVENT_RECORDING_MANAGEMENT,
        false,
        vec![
            (u::ACTIVE, Format::U8, PR | Perms::PW | Perms::EV, json!(0)),
            (
                u::SUPPORTED_CAMERA_RECORDING_CONFIG,
                Format::Tlv8,
                PR,
                b64(&[]),
            ),
            (
                u::SUPPORTED_VIDEO_RECORDING_CONFIG,
                Format::Tlv8,
                PR,
                b64(&[]),
            ),
            (
                u::SUPPORTED_AUDIO_RECORDING_CONFIG,
                Format::Tlv8,
                PR,
                b64(&[]),
            ),
            (
                u::SELECTED_CAMERA_RECORDING_CONFIG,
                Format::Tlv8,
                PR | Perms::PW,
                b64(&[]),
            ),
        ],
    );
    b.service(
        u::BUFFER_MANAGEMENT,
        false,
        vec![
            (u::BUFFER_UPLOAD_COMMAND, Format::Tlv8, ctl(), b64(&[])),
            (
                u::BUFFER_ACTIVITY_COMMAND,
                Format::Tlv8,
                Perms::PW,
                b64(&[]),
            ),
            (u::BUFFER_EVENT_COMMAND, Format::Tlv8, ctl(), b64(&[])),
            (
                u::BUFFER_EVENT_SEQUENCE_NUMBER,
                Format::U32,
                PR | Perms::EV,
                json!(0),
            ),
            (
                u::RECORDING_PUBLISHING_POINT,
                Format::Tlv8,
                PR | Perms::PW,
                b64(&[]),
            ),
        ],
    );
    // hap-python (camera_webrtc.py) links the WebRTC service and the Multi-Tier RTP in both
    // directions; without the link the Home app does not know that 8033 is the remote path for 8031.
    let iid_of = |ty: Uuid| b.services.iter().find(|s| s.ty == ty).map(|s| s.iid);
    if let (Some(rtp), Some(web)) = (iid_of(u::MULTI_TIER_RTP), iid_of(u::WEBRTC)) {
        for s in &mut b.services {
            if s.iid == rtp {
                s.linked.push(web);
            } else if s.iid == web {
                s.linked.push(rtp);
            }
        }
    }
    if legacy {
        legacy_services(&mut b, max);
    }
    Accessory {
        aid: 1,
        services: b.services,
    }
}

const SERVICE_NAMES: &[(Uuid, &str)] = &[
    (u::ACCESSORY_INFORMATION, "Accessory Information"),
    (u::HAP_PROTOCOL_INFORMATION, "HAP Protocol Information"),
    (
        u::DATA_STREAM_TRANSPORT_MANAGEMENT,
        "Data Stream Transport Management",
    ),
    (u::CAMERA_CAPABILITIES, "Camera Capabilities"),
    (u::GLOBAL_OPERATING_MODE, "Global Operating Mode"),
    (u::MOTION_SENSOR, "Motion Sensor"),
    (u::MOTION_ZONES, "Motion Zones"),
    (u::MULTI_TIER_RTP, "Multi-Tier RTP"),
    (u::WEBRTC, "WebRTC"),
    (u::CAMERA_EVENT_RECORDING_MANAGEMENT, "Recording Management"),
    (u::BUFFER_MANAGEMENT, "Buffer Management"),
    (
        u::CAMERA_RTP_STREAM_MANAGEMENT,
        "Camera RTP Stream Management",
    ),
    (u::MICROPHONE, "Microphone"),
    (u::CAMERA_OPERATING_MODE, "Camera Operating Mode"),
];

const CHAR_NAMES: &[(Uuid, &str)] = &[
    (u::IDENTIFY, "Identify"),
    (
        u::SUPPORTED_DATA_STREAM_TRANSPORT_CONFIG,
        "Supported Data Stream Transport Configuration",
    ),
    (
        u::SETUP_DATA_STREAM_TRANSPORT,
        "Setup Data Stream Transport",
    ),
    (u::MANUFACTURER, "Manufacturer"),
    (u::MODEL, "Model"),
    (u::NAME, "Name"),
    (u::SERIAL_NUMBER, "Serial Number"),
    (u::FIRMWARE_REVISION, "Firmware Revision"),
    (u::VERSION, "Version"),
    (u::CAMERA_CAPABILITIES_CHAR, "Camera Capabilities"),
    (u::HOMEKIT_CAMERA_ACTIVE, "HomeKit Camera Active"),
    (u::STREAMING_ENABLED, "Streaming Enabled"),
    (
        u::CAMERA_OPERATING_MODE_INDICATOR,
        "Camera Operating Mode Indicator",
    ),
    (u::MOTION_DETECTED, "Motion Detected"),
    (u::MOTION_ENABLED, "Motion Enabled"),
    (u::ACTIVE, "Active"),
    (u::RECORDING_AUDIO_ACTIVE, "Recording Audio Active"),
    (u::EVENT_SNAPSHOTS_ACTIVE, "Event Snapshots Active"),
    (u::PERIODIC_SNAPSHOTS_ACTIVE, "Periodic Snapshots Active"),
    (u::CAMERA_ZONES, "Camera Zones"),
    (u::STATUS_ACTIVE, "Status Active"),
    (
        u::SUPPORTED_VIDEO_STREAM_TIERS,
        "Supported Video Stream Tiers",
    ),
    (
        u::SUPPORTED_AUDIO_STREAM_TIERS,
        "Supported Audio Stream Tiers",
    ),
    (u::SUPPORTED_RTP_CONFIG, "Supported RTP Configuration"),
    (u::SETUP_ENDPOINTS, "Setup Endpoints"),
    (u::RTP_STREAMING_CONTROL, "RTP Streaming Control"),
    (u::SENSOR_UUID, "Sensor UUID"),
    (u::STREAMING_STATUS, "Streaming Status"),
    (
        u::SUPPORTED_VIDEO_STREAM_CONFIG,
        "Supported Video Stream Configuration",
    ),
    (
        u::SUPPORTED_AUDIO_STREAM_CONFIG,
        "Supported Audio Stream Configuration",
    ),
    (
        u::SELECTED_RTP_STREAM_CONFIG,
        "Selected RTP Stream Configuration",
    ),
    (u::MUTE, "Mute"),
    (u::WEBRTC_SOLICIT_OFFER, "WebRTC Solicit Offer"),
    (u::WEBRTC_PROVIDE_ANSWER, "WebRTC Provide Answer"),
    (u::WEBRTC_STREAMING_CONTROL, "WebRTC Streaming Control"),
    (
        u::NUMBER_OF_ACTIVE_SESSIONS,
        "WebRTC Number of Active Sessions",
    ),
    (u::WEBRTC_REOFFER, "WebRTC Reoffer"),
    (u::WEBRTC_UPDATE_SESSION, "WebRTC Update Session"),
    (
        u::WEBRTC_SUPPORTED_VIDEO_TIERS,
        "WebRTC Supported Video Stream Tiers",
    ),
    (
        u::WEBRTC_SUPPORTED_AUDIO_TIERS,
        "WebRTC Supported Audio Stream Tiers",
    ),
    (
        u::SUPPORTED_CAMERA_RECORDING_CONFIG,
        "Supported Camera Recording Configuration",
    ),
    (
        u::SUPPORTED_VIDEO_RECORDING_CONFIG,
        "Supported Video Recording Configuration",
    ),
    (
        u::SUPPORTED_AUDIO_RECORDING_CONFIG,
        "Supported Audio Recording Configuration",
    ),
    (
        u::SELECTED_CAMERA_RECORDING_CONFIG,
        "Selected Camera Recording Configuration",
    ),
    (u::BUFFER_UPLOAD_COMMAND, "Buffer Upload Command"),
    (u::BUFFER_ACTIVITY_COMMAND, "Buffer Activity Command"),
    (u::BUFFER_EVENT_COMMAND, "Buffer Event Command"),
    (
        u::BUFFER_EVENT_SEQUENCE_NUMBER,
        "Buffer Event Sequence Number",
    ),
    (u::RECORDING_PUBLISHING_POINT, "Recording Publishing Point"),
];

fn lookup(table: &'static [(Uuid, &'static str)], ty: &Uuid) -> String {
    table
        .iter()
        .find(|(t, _)| t == ty)
        .map_or_else(|| crate::hap::uuids::short(ty), |(_, n)| (*n).to_string())
}

pub fn service_name(ty: &Uuid) -> String {
    lookup(SERVICE_NAMES, ty)
}

pub fn char_name(ty: &Uuid) -> String {
    lookup(CHAR_NAMES, ty)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::camera::tiers::tiers_for;
    use crate::media::StreamInfo;

    fn info(width: u16, height: u16) -> StreamInfo {
        StreamInfo {
            width,
            height,
            fps: 12.0,
            has_audio_alaw: true,
        }
    }

    fn tiers() -> Vec<Tier> {
        tiers_for(&info(2560, 1440), &info(640, 360))
    }

    #[test]
    fn enabled_characteristics_are_admin_only() {
        let acc = build_accessory(
            &crate::config::Camera {
                name: "X".into(),
                main: String::new(),
                sub: String::new(),
                motion: None,
                snapshot: None,
            },
            "id",
            &tiers(),
            Uuid::nil(),
            true,
            config::MaxResolution::default(),
        );
        let mut n = 0;
        for c in acc.services.iter().flat_map(|s| &s.chars) {
            if c.ty == u::STREAMING_ENABLED || c.ty == u::MOTION_ENABLED {
                n += 1;
                assert!(
                    c.to_json()["perms"]
                        .as_array()
                        .unwrap()
                        .contains(&json!("aa"))
                );
            }
        }
        assert_eq!(n, 4);
    }

    #[test]
    fn video_tiers_tlv_parses() {
        let t = Tlv8::parse(&video_tiers_tlv(&tiers())).unwrap();
        assert_eq!(t.get_u8(1).unwrap(), Some(2));
        assert_eq!(t.get_u8(2).unwrap(), Some(99));
        let items = t.get_all(3);
        assert_eq!(items.len(), 3);
        let parsed: Vec<_> = items
            .iter()
            .map(|i| {
                let t = Tlv8::parse(i).unwrap();
                (
                    t.get_u32(1).unwrap().unwrap(),
                    t.get_u16(4).unwrap().unwrap(),
                )
            })
            .collect();
        assert_eq!(parsed, [(1, 2560), (2, 1280), (3, 640)]);
    }

    #[test]
    fn audio_tiers_tlv_parses() {
        let t = Tlv8::parse(&audio_tiers_tlv()).unwrap();
        assert_eq!(
            (t.get_u8(1).unwrap(), t.get_u8(2).unwrap()),
            (Some(3), Some(110))
        );
        let tier = Tlv8::parse(t.get(3).unwrap()).unwrap();
        assert_eq!(tier.get_u32(2).unwrap(), Some(24_000));
        assert_eq!(tier.get_u8(3).unwrap(), Some(4));
        assert_eq!(tier.get_u8(4).unwrap(), Some(2));
        assert_eq!(tier.get_u8(5).unwrap(), Some(20));
        assert_eq!(tier.get_u8(6).unwrap(), Some(1));
        assert_eq!(rtp_config_tlv(), [2, 1, 0]);
    }

    #[test]
    fn capabilities_tlv_has_sensor() {
        let sensor = Uuid::new_v5(&Uuid::NAMESPACE_URL, b"AA:BB:CC:DD:EE:FF");
        let top = Tlv8::parse(&capabilities_tlv(sensor, &tiers())).unwrap();
        let sensors = Tlv8::parse(top.get(2).unwrap()).unwrap();
        let s = Tlv8::parse(sensors.get(1).unwrap()).unwrap();
        assert_eq!(s.get(2).unwrap(), sensor.as_bytes());
        let dims = Tlv8::parse(s.get(1).unwrap()).unwrap();
        assert_eq!(dims.get_u16(1).unwrap(), Some(2560));
        assert_eq!(dims.get_u16(2).unwrap(), Some(1440));
        assert_eq!(s.get_all(5).len(), 3);
    }
}
