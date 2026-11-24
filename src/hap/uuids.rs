//! Centralized HAP UUIDs. Apple's share the base `XXXXXXXX-0000-1000-8000-0026BB765291`.

use uuid::Uuid;

const APPLE_BASE: u128 = 0x0000_1000_8000_0026_BB76_5291;

/// Apple UUID from its short form (e.g. `0x3E`).
pub const fn apple(short: u32) -> Uuid {
    Uuid::from_u128(((short as u128) << 96) | APPLE_BASE)
}

/// Short form (uppercase hex without leading zeros) if it is Apple's; otherwise the full UUID.
pub fn short(u: &Uuid) -> String {
    let v = u.as_u128();
    if v & ((1u128 << 96) - 1) == APPLE_BASE && v >> 96 <= u32::MAX as u128 {
        format!("{:X}", v >> 96)
    } else {
        u.to_string().to_uppercase()
    }
}

// Classic.
pub const ACCESSORY_INFORMATION: Uuid = apple(0x3E);
pub const HAP_PROTOCOL_INFORMATION: Uuid = apple(0xA2);
pub const VERSION: Uuid = apple(0x37);
pub const MOTION_SENSOR: Uuid = apple(0x85);
pub const MOTION_DETECTED: Uuid = apple(0x22);
pub const BATTERY: Uuid = apple(0x96);
pub const CAMERA_RTP_STREAM_MANAGEMENT: Uuid = apple(0x110);
pub const SUPPORTED_VIDEO_STREAM_CONFIG: Uuid = apple(0x114);
pub const SUPPORTED_AUDIO_STREAM_CONFIG: Uuid = apple(0x115);
pub const SUPPORTED_RTP_CONFIG: Uuid = apple(0x116);
pub const SELECTED_RTP_STREAM_CONFIG: Uuid = apple(0x117);
pub const SETUP_ENDPOINTS: Uuid = apple(0x118);
pub const STREAMING_STATUS: Uuid = apple(0x120);
pub const MICROPHONE: Uuid = apple(0x112);
pub const MUTE: Uuid = apple(0x11A);
pub const ACTIVE: Uuid = apple(0xB0);
pub const STATUS_ACTIVE: Uuid = apple(0x75);
pub const HOMEKIT_CAMERA_ACTIVE: Uuid = apple(0x21B);
pub const CAMERA_OPERATING_MODE_INDICATOR: Uuid = apple(0x21D);
pub const IDENTIFY: Uuid = apple(0x14);
pub const MANUFACTURER: Uuid = apple(0x20);
pub const MODEL: Uuid = apple(0x21);
pub const NAME: Uuid = apple(0x23);
pub const SERIAL_NUMBER: Uuid = apple(0x30);
pub const FIRMWARE_REVISION: Uuid = apple(0x52);
pub const DATA_STREAM_TRANSPORT_MANAGEMENT: Uuid = apple(0x129);
pub const SUPPORTED_DATA_STREAM_TRANSPORT_CONFIG: Uuid = apple(0x130);
pub const SETUP_DATA_STREAM_TRANSPORT: Uuid = apple(0x131);
pub const SUPPORTED_CAMERA_RECORDING_CONFIG: Uuid = apple(0x205);
pub const SUPPORTED_VIDEO_RECORDING_CONFIG: Uuid = apple(0x206);
pub const SUPPORTED_AUDIO_RECORDING_CONFIG: Uuid = apple(0x207);
pub const SELECTED_CAMERA_RECORDING_CONFIG: Uuid = apple(0x209);
pub const CAMERA_EVENT_RECORDING_MANAGEMENT: Uuid = apple(0x204);
pub const CAMERA_OPERATING_MODE: Uuid = apple(0x21A);
pub const EVENT_SNAPSHOTS_ACTIVE: Uuid = apple(0x223);
pub const PERIODIC_SNAPSHOTS_ACTIVE: Uuid = apple(0x225);
pub const RECORDING_AUDIO_ACTIVE: Uuid = apple(0x226);
pub const MOTION_ENABLED: Uuid = apple(0x8087);

// Apple guide (Developer Preview): new H.265 / multi-tier protocol. Services.
pub const BUFFER_MANAGEMENT: Uuid = apple(0x8000);
pub const CAMERA_CAPABILITIES: Uuid = apple(0x8010);
pub const MOTION_ZONES: Uuid = apple(0x8021);
pub const MULTI_TIER_RTP: Uuid = apple(0x8031);
pub const GLOBAL_OPERATING_MODE: Uuid = apple(0x8032);
pub const WEBRTC: Uuid = apple(0x8033);
pub const KEY_MANAGEMENT: Uuid = apple(0x8050);
pub const CLIENT_CERTIFICATE: Uuid = apple(0x8080);

// Characteristics of the new protocol.
pub const SENSOR_UUID: Uuid = apple(0x805B);
pub const SUPPORTED_VIDEO_STREAM_TIERS: Uuid = apple(0x8043);
pub const SUPPORTED_AUDIO_STREAM_TIERS: Uuid = apple(0x8044);
pub const CAMERA_CAPABILITIES_CHAR: Uuid = apple(0x8011);
pub const CONTRIBUTING_SENSORS: Uuid = apple(0x8086);
pub const CAMERA_KEY: Uuid = apple(0x8051);
pub const CAMERA_KEY_ID: Uuid = apple(0x8052);
pub const BUFFER_UPLOAD_COMMAND: Uuid = apple(0x8013);
pub const BUFFER_ACTIVITY_COMMAND: Uuid = apple(0x8017);
pub const BUFFER_EVENT_COMMAND: Uuid = apple(0x8014);
pub const BUFFER_EVENT_SEQUENCE_NUMBER: Uuid = apple(0x8015);
pub const RECORDING_PUBLISHING_POINT: Uuid = apple(0x8016);
pub const CAMERA_ZONES: Uuid = apple(0x8022);
pub const STREAMING_ENABLED: Uuid = apple(0x8041);
pub const RTP_STREAMING_CONTROL: Uuid = apple(0x8045);
pub const WEBRTC_SOLICIT_OFFER: Uuid = apple(0x8053);
pub const WEBRTC_PROVIDE_ANSWER: Uuid = apple(0x8054);
pub const WEBRTC_STREAMING_CONTROL: Uuid = apple(0x8056);
pub const NUMBER_OF_ACTIVE_SESSIONS: Uuid = apple(0x8057);
pub const WEBRTC_REOFFER: Uuid = apple(0x8058);
pub const WEBRTC_UPDATE_SESSION: Uuid = apple(0x805C);
pub const WEBRTC_SUPPORTED_VIDEO_TIERS: Uuid = apple(0x8059);
pub const WEBRTC_SUPPORTED_AUDIO_TIERS: Uuid = apple(0x805A);
pub const CLIENT_CSR: Uuid = apple(0x8081);
pub const CLIENT_CERTIFICATE_CHAR: Uuid = apple(0x8082);
pub const CLIENT_CERTIFICATE_STATUS: Uuid = apple(0x8083);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_forms() {
        assert_eq!(short(&apple(0x85)), "85");
        assert_eq!(short(&apple(0x3E)), "3E");
        assert_eq!(short(&apple(0x8010)), "8010");
        assert_eq!(
            apple(0x3E).to_string(),
            "0000003e-0000-1000-8000-0026bb765291"
        );
        assert_eq!(short(&MOTION_ENABLED), "8087");
        let other = Uuid::parse_str("12345678-1234-1234-1234-123456789abc").unwrap();
        assert_eq!(short(&other), "12345678-1234-1234-1234-123456789ABC");
    }
}
