//! HomeKit camera accessory: services for the new protocol (HKSV 17.99), tiers and handler.

pub mod legacy;
pub mod recording;
pub mod rtp_session;
pub mod services;
pub mod setup_endpoints;
pub mod sframe;
pub mod tiers;
pub mod webrtc;

use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use serde_json::Value;
use uuid::Uuid;

use crate::hap::model::{Accessory, Format, Handler, ResourceRequest};
use crate::hap::tlv8::Tlv8;
use crate::hap::uuids as u;
use crate::media::StreamInfo;
use crate::media::ingest::Stream;
use crate::media::snapshot::Snapshotter;
pub use rtp_session::Sessions;
use rtp_session::{StartCommand, Status, status_tlv};
pub use services::{build_accessory, build_classic_accessory};
pub use tiers::tiers_for;
pub use webrtc::WebRtc;

/// HAP category 17 = IP Camera. Must match the accessory's services: advertising
/// ci=17 without camera services (only a motion sensor) makes the Home app get stuck
/// on "Looking for the accessory".
pub const CAMERA_CATEGORY: u8 = 17;

const INFO_WAIT: Duration = Duration::from_secs(15);
const DEFAULT_MAIN: (u16, u16) = (2560, 1440);
const DEFAULT_SUB: (u16, u16) = (640, 360);

/// Stable UUID v5 for the sensor, derived from the device_id.
pub fn sensor_uuid(device_id: &str) -> Uuid {
    Uuid::new_v5(&Uuid::NAMESPACE_URL, device_id.as_bytes())
}

/// Waits (up to 15 s) for the main and sub info; anything missing uses default values.
pub async fn wait_infos(name: &str, main: &Stream, sub: &Stream) -> (StreamInfo, StreamInfo) {
    let deadline = Instant::now() + INFO_WAIT;
    while (main.info().is_none() || sub.info().is_none()) && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let pick = |label: &str, got: Option<StreamInfo>, (width, height): (u16, u16)| {
        got.unwrap_or_else(|| {
            tracing::warn!("{name}: no stream info for {label} after 15 s, using {width}x{height}");
            StreamInfo {
                width,
                height,
                fps: 25.0,
                has_audio_alaw: false,
            }
        })
    };
    let (m, s) = (
        pick("main", main.info(), DEFAULT_MAIN),
        pick("sub", sub.info(), DEFAULT_SUB),
    );
    tracing::info!(
        "{name}: main {}x{} {:.1} fps (audio alaw={}), sub {}x{} {:.1} fps (audio alaw={})",
        m.width,
        m.height,
        m.fps,
        m.has_audio_alaw,
        s.width,
        s.height,
        s.fps,
        s.has_audio_alaw
    );
    (m, s)
}

pub struct CameraHandler {
    pub accessory: Arc<RwLock<Accessory>>,
    pub snapshotter: Arc<Snapshotter>,
    pub sessions: Arc<Sessions>,
    pub webrtc: Arc<webrtc::WebRtc>,
    pub hds: Arc<crate::hds::HdsServer>,
}

/// TLV8/Data as hex (the model carries them as base64); the rest as JSON. Max. 512 characters.
fn short_value(format: Format, v: &Value) -> String {
    let mut s = match (format, v.as_str()) {
        (Format::Tlv8 | Format::Data, Some(b)) => {
            B64.decode(b).map_or_else(|_| b.to_string(), hex::encode)
        }
        _ => v.to_string(),
    };
    if s.len() > 512 {
        s.truncate(512);
        s.push('…');
    }
    s
}

/// Well-formed error response for the control points not yet implemented
/// (Setup Endpoints/RTP: Task 12, WebRTC: Task 15). Returns `None` if `ty` is not one of them.
fn control_error(ty: &Uuid, raw: &[u8]) -> Option<Vec<u8>> {
    let sid = Tlv8::parse(raw)
        .ok()
        .and_then(|t| t.get(1).filter(|s| s.len() == 16).map(<[u8]>::to_vec));
    let with_sid = |status_tag: u8, status: u8| {
        let t = match &sid {
            Some(s) => Tlv8::new().push(1, s),
            None => Tlv8::new(),
        };
        t.push_u8(status_tag, status).encode()
    };
    Some(if *ty == u::SETUP_ENDPOINTS {
        with_sid(2, 2) // Setup Endpoints status 2 = Error
    } else if *ty == u::RTP_STREAMING_CONTROL {
        with_sid(2, 4) // RTP Streaming status 4 = Error
    } else if *ty == u::WEBRTC_SOLICIT_OFFER {
        Tlv8::new().push_u8(4, 2).encode() // Solicit Offer status 2 = Error
    } else if *ty == u::WEBRTC_REOFFER {
        with_sid(3, 3) // Reoffer: status in type 3; WebRTC Streaming status 3 = Error
    } else if [
        u::WEBRTC_PROVIDE_ANSWER,
        u::WEBRTC_STREAMING_CONTROL,
        u::WEBRTC_UPDATE_SESSION,
    ]
    .contains(ty)
    {
        with_sid(2, 3)
    } else {
        return None;
    })
}

/// Log line for a write. If it is sensitive (SRTP keys, SDP) it never includes the value.
fn write_log_line(name: &str, ty: &Uuid, format: Format, v: &Value, raw: &[u8]) -> String {
    if is_sensitive(ty) {
        let sid = Tlv8::parse(raw)
            .ok()
            .and_then(|t| t.get(1).filter(|s| s.len() == 16).map(hex::encode));
        format!(
            "{name} ({} bytes, session {})",
            raw.len(),
            sid.as_deref().unwrap_or("-")
        )
    } else {
        format!("{name} = {}", short_value(format, v))
    }
}

/// Characteristics whose write carries secrets (SRTP keys, SDP).
fn is_sensitive(ty: &Uuid) -> bool {
    [
        u::SETUP_ENDPOINTS,
        u::WEBRTC_SOLICIT_OFFER,
        u::WEBRTC_PROVIDE_ANSWER,
        u::WEBRTC_STREAMING_CONTROL,
        u::WEBRTC_REOFFER,
        u::WEBRTC_UPDATE_SESSION,
    ]
    .contains(ty)
}

/// Writes that Task 19 will implement; for now they are accepted with no effect.
fn is_buffer_command(ty: &Uuid) -> bool {
    [
        u::BUFFER_UPLOAD_COMMAND,
        u::BUFFER_ACTIVITY_COMMAND,
        u::BUFFER_EVENT_COMMAND,
        u::RECORDING_PUBLISHING_POINT,
    ]
    .contains(ty)
}

/// `WebRtc` hook: stores Number of Active Sessions in the model and notifies.
pub fn count_hook(
    acc: Arc<RwLock<Accessory>>,
    notifier: crate::hap::server::Notifier,
) -> Arc<dyn Fn(u8) + Send + Sync> {
    Arc::new(move |n| {
        let iid = {
            let mut a = acc.write().unwrap();
            let Some(c) = a
                .services
                .iter_mut()
                .filter(|s| s.ty == u::WEBRTC)
                .flat_map(|s| &mut s.chars)
                .find(|c| c.ty == u::NUMBER_OF_ACTIVE_SESSIONS)
            else {
                return;
            };
            if c.value.as_u64() == Some(u64::from(n)) {
                return;
            }
            c.value = Value::from(n);
            c.iid
        };
        notifier.notify(iid, Value::from(n));
    })
}

impl CameraHandler {
    /// Boolean/integer value of a characteristic (`true` if missing, as with Status Active).
    fn flag(&self, svc: Uuid, ch: Uuid) -> bool {
        let acc = self.accessory.read().unwrap();
        acc.services
            .iter()
            .filter(|s| s.ty == svc)
            .flat_map(|s| &s.chars)
            .find(|c| c.ty == ch)
            .is_none_or(|c| {
                c.value
                    .as_bool()
                    .unwrap_or_else(|| c.value.as_u64() != Some(0))
            })
    }

    /// Reason WebRTC cannot stream right now (Solicit Offer state).
    fn webrtc_refusal(&self) -> Option<u8> {
        if !self.flag(u::GLOBAL_OPERATING_MODE, u::HOMEKIT_CAMERA_ACTIVE) {
            return Some(webrtc::SO_PRIVACY);
        }
        (!(self.flag(u::WEBRTC, u::STREAMING_ENABLED)
            && self.flag(u::GLOBAL_OPERATING_MODE, u::STREAMING_ENABLED)))
        .then_some(webrtc::SO_ERROR)
    }

    /// Writes for the WebRTC service; `None` if `ty` does not belong to that service.
    fn webrtc_write(&self, ty: &Uuid, raw: &[u8]) -> Option<Vec<u8>> {
        use webrtc as w;
        let conn = crate::hap::server::current_conn();
        let sframe_wanted = w::parse_solicit(raw);
        Some(if *ty == u::WEBRTC_SOLICIT_OFFER {
            if let Some(st) = self.webrtc_refusal() {
                tracing::info!("WebRTC Solicit Offer rejected (status {st})");
                return Some(w::solicit_error(st));
            }
            match self.webrtc.solicit(conn) {
                Ok(s) => {
                    tracing::info!(
                        "WebRTC {}: offer ready ({} bytes of SDP, SFrame requested by the controller: {:?})",
                        hex::encode(&s.sid[..4]),
                        s.sdp.len(),
                        sframe_wanted
                    );
                    w::solicit_response(&s)
                }
                Err(e) => {
                    tracing::warn!("WebRTC Solicit Offer failed: {e:#}");
                    w::solicit_error(w::SO_ERROR)
                }
            }
        } else if *ty == u::WEBRTC_PROVIDE_ANSWER {
            let Some((sid, sdp, cands)) = w::parse_answer_tlv(raw) else {
                return Some(w::status_tlv(None, w::ST_ERROR));
            };
            tracing::info!(
                "WebRTC {}: answer received ({} bytes of SDP, {} candidates)",
                hex::encode(&sid[..4]),
                sdp.len(),
                cands.len()
            );
            w::status_tlv(Some(&sid), self.webrtc.answer(sid, &sdp, &cands))
        } else if *ty == u::WEBRTC_STREAMING_CONTROL {
            let t = Tlv8::parse(raw).ok()?;
            let Some(sid) = w::parse_sid(&t) else {
                return Some(w::status_tlv(None, w::ST_ERROR));
            };
            let st = if t.get_u8(2).ok().flatten() == Some(1) {
                self.webrtc.end(&sid)
            } else {
                w::ST_ERROR
            };
            w::status_tlv(Some(&sid), st)
        } else if *ty == u::WEBRTC_REOFFER {
            let t = Tlv8::parse(raw).ok()?;
            let Some(sid) = w::parse_sid(&t) else {
                return Some(Tlv8::new().push_u8(3, w::ST_ERROR).encode());
            };
            let sdp = t.get(2).and_then(|b| std::str::from_utf8(b).ok());
            let r = sdp.map_or(Err(w::ST_ERROR), |o| self.webrtc.reoffer(&sid, o));
            w::reoffer_response(&sid, r)
        } else if *ty == u::WEBRTC_UPDATE_SESSION {
            let t = Tlv8::parse(raw).ok()?;
            let Some(sid) = w::parse_sid(&t) else {
                return Some(w::status_tlv(None, w::ST_ERROR));
            };
            let st = self
                .webrtc
                .update(&sid, t.get_all(2).len(), t.get_all(3).len());
            w::status_tlv(Some(&sid), st)
        } else {
            return None;
        })
    }
}

impl CameraHandler {
    /// Status Active = Streaming Enabled (8031) and (8032) and HomeKit Camera Active.
    fn refresh_status_active(acc: &mut Accessory) {
        let truthy = |a: &Accessory, svc: Uuid, ch: Uuid| {
            a.services
                .iter()
                .filter(|s| s.ty == svc)
                .flat_map(|s| &s.chars)
                .find(|c| c.ty == ch)
                .is_none_or(|c| {
                    c.value
                        .as_bool()
                        .unwrap_or_else(|| c.value.as_u64() != Some(0))
                })
        };
        let active = truthy(acc, u::MULTI_TIER_RTP, u::STREAMING_ENABLED)
            && truthy(acc, u::GLOBAL_OPERATING_MODE, u::STREAMING_ENABLED)
            && truthy(acc, u::GLOBAL_OPERATING_MODE, u::HOMEKIT_CAMERA_ACTIVE);
        if let Some(c) = acc
            .services
            .iter_mut()
            .filter(|s| s.ty == u::MULTI_TIER_RTP)
            .flat_map(|s| &mut s.chars)
            .find(|c| c.ty == u::STATUS_ACTIVE)
        {
            c.value = Value::Bool(active);
        }
    }
}

impl CameraHandler {
    fn status_active(&self) -> bool {
        let acc = self.accessory.read().unwrap();
        acc.services
            .iter()
            .filter(|s| s.ty == u::MULTI_TIER_RTP)
            .flat_map(|s| &s.chars)
            .find(|c| c.ty == u::STATUS_ACTIVE)
            .is_none_or(|c| c.value.as_bool().unwrap_or(true))
    }

    /// Setup Endpoints: `None` if it could not be handled (the caller responds with an error).
    fn setup_endpoints(&self, raw: &[u8]) -> Option<Vec<u8>> {
        let req = match setup_endpoints::parse_request(raw) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("invalid Setup Endpoints: {e:#}");
                return control_error(&u::SETUP_ENDPOINTS, raw);
            }
        };
        let sid = req.session_id;
        let controller = req.addr;
        match self
            .sessions
            .prepare(req, crate::hap::server::current_conn())
        {
            Ok(resp) => {
                tracing::info!(
                    "Setup Endpoints ok, session {}, controller {controller}",
                    hex::encode(&sid[..4])
                );
                Some(resp)
            }
            Err(e) => {
                tracing::warn!("Setup Endpoints failed: {e:#}");
                control_error(&u::SETUP_ENDPOINTS, raw)
            }
        }
    }

    /// Selected RTP Stream Configuration (117, classic H.264 service): Start/End/Reconfigure.
    /// Error = the write fails (HAP responds with an error to the controller).
    async fn selected_stream(&self, raw: &[u8]) -> Result<()> {
        let (sid, command) = legacy::parse_control(raw)?;
        let status = match command {
            0 => {
                // End: an already-ended session is not an error.
                self.sessions.end(sid).await;
                Status::Success
            }
            // Reconfigure: HAP-NodeJS does not implement it and go2rtc ignores everything except Start/End;
            // iOS only sends the resolution/bitrate it wants right now (partial). It is acknowledged
            // without restarting ffmpeg (a restart would cut the image); unknown session = error.
            4 => {
                let r = legacy::parse_reconfigure(raw)?;
                tracing::info!(
                    "Reconfigure session {}: {:?}x{:?} fps {:?} max {:?} kbps (without restarting)",
                    hex::encode(&sid[..4]),
                    r.width,
                    r.height,
                    r.fps,
                    r.max_kbps
                );
                if self.sessions.is_running(&sid) {
                    Status::Success
                } else {
                    Status::UnknownSession
                }
            }
            1 if !self.status_active() => {
                tracing::warn!("Selected RTP Stream Configuration: Status Active = false");
                Status::Error
            }
            1 => match legacy::parse_selected(raw) {
                Ok(sel) => self.sessions.start_legacy(sel).await,
                Err(e) => {
                    tracing::warn!("invalid Selected RTP Stream Configuration: {e:#}");
                    Status::Error
                }
            },
            // Suspend/Resume: no effect (the stream keeps going; the Home app sends it when the view is hidden).
            _ => Status::Success,
        };
        tracing::info!(
            "Selected RTP Stream Configuration session {} cmd {command} -> {status:?}",
            hex::encode(&sid[..4])
        );
        anyhow::ensure!(status == Status::Success, "could not handle: {status:?}");
        Ok(())
    }

    async fn streaming_control(&self, raw: &[u8]) -> Vec<u8> {
        let Ok(cmd) = StartCommand::parse(raw) else {
            tracing::warn!("invalid RTP Streaming Control");
            return status_tlv(None, Status::Error);
        };
        let (sid, command) = (cmd.session_id, cmd.command);
        let status = match command {
            1 => self.sessions.end(sid).await,
            2 if !self.status_active() => {
                tracing::warn!("Start rejected: Status Active = false");
                Status::Error
            }
            2 => self.sessions.start(cmd).await,
            _ => Status::Error,
        };
        tracing::info!(
            "RTP Streaming Control session {} cmd {command} -> {status:?}",
            hex::encode(&sid[..4])
        );
        status_tlv(Some(&sid), status)
    }
}

#[async_trait::async_trait]
impl Handler for CameraHandler {
    async fn read(&self, iid: u64) -> Result<Value> {
        let acc = self.accessory.read().unwrap();
        let c = acc.find(iid).ok_or_else(|| anyhow!("unknown iid {iid}"))?;
        Ok(c.value.clone())
    }

    async fn write(&self, iid: u64, v: Value, response: bool) -> Result<Option<Value>> {
        // The (std) lock cannot cross an await: it is taken only to register and read the type.
        let (ty, raw) = {
            let mut acc = self.accessory.write().unwrap();
            let svc = acc
                .services
                .iter()
                .find(|s| s.chars.iter().any(|c| c.iid == iid))
                .map(|s| services::service_name(&s.ty))
                .ok_or_else(|| anyhow!("unknown iid {iid}"))?;
            let c = acc
                .find_mut(iid)
                .ok_or_else(|| anyhow!("unknown iid {iid}"))?;
            let name = format!("write {svc}.{}", services::char_name(&c.ty));
            let raw = v
                .as_str()
                .and_then(|s| B64.decode(s).ok())
                .unwrap_or_default();
            tracing::info!("{}", write_log_line(&name, &c.ty, c.format, &v, &raw));
            if c.ty == u::IDENTIFY || is_buffer_command(&c.ty) {
                return Ok(None);
            }
            (c.ty, raw)
        };
        let resp = if ty == u::SETUP_ENDPOINTS {
            self.setup_endpoints(&raw)
        } else if ty == u::RTP_STREAMING_CONTROL {
            Some(self.streaming_control(&raw).await)
        } else if ty == u::SETUP_DATA_STREAM_TRANSPORT {
            Some(self.hds.setup(&raw).await)
        } else if ty == u::SELECTED_RTP_STREAM_CONFIG {
            self.selected_stream(&raw).await?;
            None
        } else {
            self.webrtc_write(&ty, &raw)
                .or_else(|| control_error(&ty, &raw))
        };
        let mut acc = self.accessory.write().unwrap();
        let c = acc
            .find_mut(iid)
            .ok_or_else(|| anyhow!("unknown iid {iid}"))?;
        if let Some(resp) = resp {
            // The Home app reads the result with a later read or with write-response.
            c.value = services::b64(&resp);
            return Ok(response.then(|| c.value.clone()));
        }
        c.value = v;
        Self::refresh_status_active(&mut acc);
        drop(acc);
        // Turning off streaming or private mode closes the ongoing WebRTC sessions.
        if self.webrtc_refusal().is_some() {
            self.webrtc.end_all();
        }
        Ok(None)
    }

    async fn resource(&self, req: ResourceRequest) -> Result<Vec<u8>> {
        self.snapshotter.get(req.width, req.height).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Camera;
    use crate::hap::uuids::short;
    use serde_json::json;

    fn camera() -> Camera {
        Camera {
            name: "Patio".into(),
            main: "rtsp://x/main".into(),
            sub: "rtsp://x/sub".into(),
            motion: None,
            snapshot: None,
        }
    }

    fn info(width: u16, height: u16) -> StreamInfo {
        StreamInfo {
            width,
            height,
            fps: 12.0,
            has_audio_alaw: true,
        }
    }

    fn accessory() -> Accessory {
        let tiers = tiers_for(&info(2560, 1440), &info(640, 360));
        build_accessory(
            &camera(),
            "AA:BB:CC:DD:EE:FF",
            &tiers,
            sensor_uuid("AA:BB:CC:DD:EE:FF"),
            true,
            Default::default(),
        )
    }

    fn handler() -> CameraHandler {
        CameraHandler {
            accessory: Arc::new(RwLock::new(accessory())),
            snapshotter: Arc::new(Snapshotter::new(
                Stream::spawn("rtsp://127.0.0.1:1/none".into(), 1),
                None,
            )),
            sessions: Arc::new(Sessions::new(
                Stream::detached(),
                Stream::detached(),
                vec![],
                crate::config::HwAccel::None,
            )),
            webrtc: WebRtc::new(
                Stream::detached(),
                Stream::detached(),
                tiers_for(&info(2560, 1440), &info(640, 360)).pop().unwrap(),
                Arc::new(|_| {}),
            ),
            hds: crate::hds::HdsServer::new(),
        }
    }

    fn iid_of(h: &CameraHandler, svc: Uuid, ch: Uuid) -> u64 {
        let acc = h.accessory.read().unwrap();
        acc.services
            .iter()
            .filter(|s| s.ty == svc)
            .flat_map(|s| &s.chars)
            .find(|c| c.ty == ch)
            .unwrap()
            .iid
    }

    #[test]
    fn accessory_json_contains_services() {
        let j = accessory().to_json();
        let types: Vec<&str> = j["accessories"][0]["services"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s["type"].as_str().unwrap())
            .collect();
        for t in ["8010", "8032", "85", "8031", "8033", "204", "8000"] {
            assert!(types.contains(&t), "missing service {t}: {types:?}");
        }
        assert_eq!(short(&u::MULTI_TIER_RTP), "8031");
    }

    #[test]
    fn sensor_uuid_is_stable() {
        assert_eq!(sensor_uuid("AA"), sensor_uuid("AA"));
        assert_ne!(sensor_uuid("AA"), sensor_uuid("BB"));
    }

    #[tokio::test]
    async fn rw_write_is_stored_and_updates_status_active() {
        let h = handler();
        let se = iid_of(&h, u::MULTI_TIER_RTP, u::STREAMING_ENABLED);
        let st = iid_of(&h, u::MULTI_TIER_RTP, u::STATUS_ACTIVE);
        assert_eq!(h.read(st).await.unwrap(), json!(true));
        h.write(se, json!(false), false).await.unwrap();
        assert_eq!(h.read(se).await.unwrap(), json!(false));
        assert_eq!(h.read(st).await.unwrap(), json!(false));
        let ca = iid_of(&h, u::GLOBAL_OPERATING_MODE, u::HOMEKIT_CAMERA_ACTIVE);
        h.write(se, json!(true), false).await.unwrap();
        h.write(ca, json!(0), false).await.unwrap();
        assert_eq!(h.read(st).await.unwrap(), json!(false));
    }

    #[tokio::test]
    async fn setup_endpoints_write_answers_error_with_session() {
        let h = handler();
        let iid = iid_of(&h, u::MULTI_TIER_RTP, u::SETUP_ENDPOINTS);
        let sid = [7u8; 16];
        let req = Tlv8::new().push(1, &sid).encode();
        let resp = h
            .write(iid, services::b64(&req), true)
            .await
            .unwrap()
            .unwrap();
        let t = Tlv8::parse(&B64.decode(resp.as_str().unwrap()).unwrap()).unwrap();
        assert_eq!(t.get(1).unwrap(), sid);
        assert_eq!(t.get_u8(2).unwrap(), Some(2));
    }

    fn loopback_setup(sid: [u8; 16]) -> Vec<u8> {
        let srtp = Tlv8::new()
            .push_u8(1, 0)
            .push(2, &[1; 16])
            .push(3, &[2; 14])
            .encode();
        let addr = Tlv8::new()
            .push_u8(1, 0)
            .push(2, b"127.0.0.1")
            .push(3, &5000u16.to_le_bytes())
            .push(4, &5002u16.to_le_bytes())
            .encode();
        Tlv8::new()
            .push(1, &sid)
            .push(3, &addr)
            .push(4, &srtp)
            .push(5, &srtp)
            .encode()
    }

    async fn write_tlv(h: &CameraHandler, iid: u64, t: &[u8]) -> Tlv8 {
        let r = h.write(iid, services::b64(t), true).await.unwrap().unwrap();
        Tlv8::parse(&B64.decode(r.as_str().unwrap()).unwrap()).unwrap()
    }

    #[tokio::test]
    async fn setup_endpoints_write_succeeds_with_ssrcs() {
        let h = handler();
        let iid = iid_of(&h, u::MULTI_TIER_RTP, u::SETUP_ENDPOINTS);
        let t = write_tlv(&h, iid, &loopback_setup([5; 16])).await;
        assert_eq!(t.get(1).unwrap(), [5; 16]);
        assert_eq!(t.get_u8(2).unwrap(), Some(0));
        assert!(t.get(6).is_some() && t.get(7).is_some());
    }

    #[tokio::test]
    async fn start_rejected_when_streaming_disabled() {
        let h = handler();
        let setup = iid_of(&h, u::MULTI_TIER_RTP, u::SETUP_ENDPOINTS);
        let ctl = iid_of(&h, u::MULTI_TIER_RTP, u::RTP_STREAMING_CONTROL);
        let se = iid_of(&h, u::MULTI_TIER_RTP, u::STREAMING_ENABLED);
        write_tlv(&h, setup, &loopback_setup([6; 16])).await;
        h.write(se, json!(false), false).await.unwrap();
        let start = Tlv8::new()
            .push(1, &[6; 16])
            .push_u8(2, 2)
            .push_u32(3, 3)
            .encode();
        let t = write_tlv(&h, ctl, &start).await;
        assert_eq!(t.get_u8(2).unwrap(), Some(Status::Error as u8));
        assert_eq!(h.sessions.active(), 0);
    }

    #[test]
    fn sensitive_write_log_has_no_value() {
        let sid = [0xabu8; 16];
        let tlv = Tlv8::new().push(1, &sid).push(4, &[0x5a; 40]).encode();
        let v = services::b64(&tlv);
        let l = write_log_line("w", &u::SETUP_ENDPOINTS, Format::Tlv8, &v, &tlv);
        assert!(l.contains(&hex::encode(sid)) && l.contains("bytes"));
        assert!(!l.contains(&hex::encode([0x5au8; 8])));
        assert!(!l.contains(v.as_str().unwrap()));
        // not sensitive: the value is shown
        let l = write_log_line("w", &u::STREAMING_ENABLED, Format::Bool, &json!(true), &[]);
        assert!(l.contains("true"));
    }

    #[tokio::test]
    async fn webrtc_solicit_offer_succeeds_and_respects_status() {
        let h = handler();
        let iid = iid_of(&h, u::WEBRTC, u::WEBRTC_SOLICIT_OFFER);
        let opts = Tlv8::new().push(1, &Tlv8::new().push_u8(1, 1).encode());
        let t = write_tlv(&h, iid, &opts.encode()).await;
        assert_eq!(t.get_u8(4).unwrap(), Some(0));
        assert_eq!(t.get(1).unwrap().len(), 16);
        assert!(t.get(2).is_some() && t.get(5).is_some());
        // Streaming Enabled (WebRTC) false -> Error; HomeKit Camera Active 0 -> Privacy.
        let se = iid_of(&h, u::WEBRTC, u::STREAMING_ENABLED);
        h.write(se, json!(false), false).await.unwrap();
        let t = write_tlv(&h, iid, &opts.encode()).await;
        assert_eq!(t.get_u8(4).unwrap(), Some(2));
        h.write(se, json!(true), false).await.unwrap();
        let ca = iid_of(&h, u::GLOBAL_OPERATING_MODE, u::HOMEKIT_CAMERA_ACTIVE);
        h.write(ca, json!(0), false).await.unwrap();
        let t = write_tlv(&h, iid, &opts.encode()).await;
        assert_eq!(t.get_u8(4).unwrap(), Some(1));
    }

    #[tokio::test]
    async fn webrtc_unknown_session_statuses() {
        let h = handler();
        let end = iid_of(&h, u::WEBRTC, u::WEBRTC_STREAMING_CONTROL);
        let req = Tlv8::new().push(1, &[3; 16]).push_u8(2, 1).encode();
        let t = write_tlv(&h, end, &req).await;
        assert_eq!(t.get_u8(2).unwrap(), Some(1));
        let upd = iid_of(&h, u::WEBRTC, u::WEBRTC_UPDATE_SESSION);
        let t = write_tlv(&h, upd, &Tlv8::new().push(1, &[3; 16]).encode()).await;
        assert_eq!(t.get_u8(2).unwrap(), Some(1));
    }

    #[test]
    fn webrtc_service_is_linked_with_multi_tier_both_ways() {
        let acc = accessory();
        let iid = |ty: Uuid| acc.services.iter().find(|s| s.ty == ty).unwrap().iid;
        let j = acc.to_json();
        let svc = |id: u64| {
            j["accessories"][0]["services"]
                .as_array()
                .unwrap()
                .iter()
                .find(|s| s["iid"] == id)
                .unwrap()
                .clone()
        };
        assert_eq!(
            svc(iid(u::MULTI_TIER_RTP))["linked"],
            json!([iid(u::WEBRTC)])
        );
        assert_eq!(
            svc(iid(u::WEBRTC))["linked"],
            json!([iid(u::MULTI_TIER_RTP)])
        );
    }

    fn svc(acc: &Accessory, ty: Uuid) -> &crate::hap::model::Service {
        acc.services.iter().find(|s| s.ty == ty).unwrap()
    }

    /// Service 110 with the same set of characteristics as go2rtc
    /// (pkg/hap/camera/accessory.go): 120, 114, 115, 116, B0, 117 and 118, in that order.
    #[test]
    fn legacy_service_matches_go2rtc_characteristics() {
        let acc = accessory();
        let rtp = svc(&acc, u::CAMERA_RTP_STREAM_MANAGEMENT);
        let tys: Vec<String> = rtp.chars.iter().map(|c| short(&c.ty)).collect();
        assert_eq!(tys, ["120", "114", "115", "116", "B0", "117", "118"]);
        let perms = |i: usize| {
            rtp.chars[i].to_json()["perms"]
                .as_array()
                .unwrap()
                .iter()
                .map(|p| p.as_str().unwrap().to_string())
                .collect::<Vec<_>>()
        };
        assert_eq!(perms(0), ["pr", "ev"]);
        assert_eq!(perms(1), ["pr"]);
        assert_eq!(perms(5), ["pr", "pw"]);
        assert_eq!(perms(6), ["pr", "pw"]);
        // 117 and 118 empty ("important empty" in go2rtc); Active = 1.
        assert_eq!(rtp.chars[5].value, json!(""));
        assert_eq!(rtp.chars[6].value, json!(""));
        assert_eq!(rtp.chars[4].value, json!(1));
        let mic = svc(&acc, u::MICROPHONE);
        assert_eq!(short(&mic.chars[0].ty), "11A");
        // HSV3 follows, and the classic service is not the primary one.
        assert!(svc(&acc, u::MULTI_TIER_RTP).primary && !rtp.primary);
    }

    #[test]
    fn legacy_off_has_no_classic_service() {
        let tiers = tiers_for(&info(2560, 1440), &info(640, 360));
        let acc = build_accessory(
            &camera(),
            "id",
            &tiers,
            sensor_uuid("id"),
            false,
            Default::default(),
        );
        assert!(
            acc.services
                .iter()
                .all(|s| s.ty != u::CAMERA_RTP_STREAM_MANAGEMENT && s.ty != u::MICROPHONE)
        );
    }

    #[test]
    fn separate_mode_distinct_identity() {
        use crate::hap::store::FileStore;
        let dir = tempfile::tempdir().unwrap();
        let main = FileStore::open(dir.path(), "patio").unwrap();
        let key = legacy::separate_key("patio");
        let sep = FileStore::open(dir.path(), &key).unwrap();
        assert_ne!(main.identity().device_id, sep.identity().device_id);
        assert_eq!(legacy::separate_name("Patio"), "Patio (H.264)");
        let acc = build_classic_accessory(
            "Patio (H.264)",
            &sep.identity().device_id,
            Default::default(),
        );
        let tys: Vec<String> = acc.services.iter().map(|s| short(&s.ty)).collect();
        assert_eq!(tys, ["3E", "A2", "110", "112", "85", "129", "204", "21A"]);
    }

    #[tokio::test]
    async fn setup_data_stream_transport_write_response() {
        let mut h = handler();
        h.accessory = Arc::new(RwLock::new(build_classic_accessory(
            "Patio",
            "AA:BB:CC:DD:EE:FF",
            Default::default(),
        )));
        let iid = iid_of(
            &h,
            u::DATA_STREAM_TRANSPORT_MANAGEMENT,
            u::SETUP_DATA_STREAM_TRANSPORT,
        );
        // Without a verified session (tests) the setup is rejected with status 1, well-formed.
        let req = Tlv8::new()
            .push_u8(1, 0)
            .push_u8(2, 0)
            .push(3, &[9; 32])
            .encode();
        let t = write_tlv(&h, iid, &req).await;
        assert_eq!(t.get_u8(1).unwrap(), Some(1));
        assert!(t.get(3).is_none());
    }

    fn classic_iids(h: &CameraHandler) -> (u64, u64) {
        (
            iid_of(h, u::CAMERA_RTP_STREAM_MANAGEMENT, u::SETUP_ENDPOINTS),
            iid_of(
                h,
                u::CAMERA_RTP_STREAM_MANAGEMENT,
                u::SELECTED_RTP_STREAM_CONFIG,
            ),
        )
    }

    fn selected(sid: [u8; 16], cmd: u8) -> Vec<u8> {
        let ctl = Tlv8::new().push(1, &sid).push_u8(2, cmd).encode();
        if cmd == 0 {
            return Tlv8::new().push(1, &ctl).encode();
        }
        let sel = legacy::SelectedConfig {
            session_id: sid,
            video: legacy::VideoSel {
                width: 640,
                height: 360,
                fps: 25,
                profile: 1,
                level: 0,
                pt: 99,
                max_kbps: 299,
                mtu: 1378,
            },
            audio: None,
        };
        let v = &sel.video;
        let vparams = Tlv8::new()
            .push_u8(1, v.profile)
            .push_u8(2, v.level)
            .push_u8(3, 0);
        let vattrs = Tlv8::new()
            .push(1, &v.width.to_le_bytes())
            .push(2, &v.height.to_le_bytes())
            .push_u8(3, v.fps);
        let vrtp = Tlv8::new()
            .push_u8(1, 99)
            .push_u32(2, 1)
            .push(3, &v.max_kbps.to_le_bytes());
        let video = Tlv8::new()
            .push_u8(1, 0)
            .push(2, &vparams.encode())
            .push(3, &vattrs.encode())
            .push(4, &vrtp.encode());
        Tlv8::new().push(1, &ctl).push(2, &video.encode()).encode()
    }

    #[tokio::test]
    async fn classic_setup_endpoints_then_selected_stream_flow() {
        let h = handler();
        let (setup, sel) = classic_iids(&h);
        let sid = [8; 16];
        // Classic 118: same response (success + SSRC) as the Multi-Tier one.
        let t = write_tlv(&h, setup, &loopback_setup(sid)).await;
        assert_eq!(t.get_u8(2).unwrap(), Some(0));
        assert!(t.get(6).is_some() && t.get(7).is_some());
        // Start of a session without a prior Setup Endpoints: the write fails.
        assert!(
            h.write(sel, services::b64(&selected([5; 16], 1)), false)
                .await
                .is_err()
        );
        // Partial Reconfigure (captured from iOS) for a session that is not running: error, not panic.
        let mut rc = vec![0x01, 0x15, 0x02, 0x01, 0x04, 0x01, 0x10];
        rc.extend_from_slice(&[5; 16]);
        rc.extend_from_slice(&[
            0x02, 0x19, 0x03, 0x0b, 0x01, 0x02, 0x80, 0x02, 0x02, 0x02, 0x68, 0x01, 0x03, 0x01,
            0x1e, 0x04, 0x0a, 0x03, 0x02, 0x84, 0x00, 0x04, 0x04, 0x00, 0x00, 0x00, 0x00,
        ]);
        assert!(h.write(sel, services::b64(&rc), false).await.is_err());
        // End of a nonexistent session is not an error.
        assert!(
            h.write(sel, services::b64(&selected([5; 16], 0)), false)
                .await
                .is_ok()
        );
        assert_eq!(h.sessions.active(), 0);
        // Garbage -> error, not panic.
        assert!(
            h.write(sel, services::b64(&[1, 2, 3]), false)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn count_hook_updates_number_of_active_sessions() {
        let h = handler();
        let hook = count_hook(h.accessory.clone(), crate::hap::server::Notifier::new());
        hook(3);
        let iid = iid_of(&h, u::WEBRTC, u::NUMBER_OF_ACTIVE_SESSIONS);
        assert_eq!(h.read(iid).await.unwrap(), json!(3));
    }
}
