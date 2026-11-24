//! Motion source from the camera itself (DVRIP; ONVIF is not available on iCSee).
pub mod dvrip;

use std::sync::{Arc, RwLock};

use anyhow::{Result, bail};
use serde_json::Value;
use tokio::sync::watch;

use crate::hap::model::Accessory;
use crate::hap::server::Notifier;
use crate::hap::uuids as u;

/// The scheme picks the implementation. Fails fast on an invalid URL; the connection
/// (and its retries) runs in the background.
pub fn spawn(url: &str, hold: std::time::Duration) -> Result<watch::Receiver<bool>> {
    match url.split_once("://").map(|(s, _)| s) {
        Some("dvrip") => dvrip::spawn(url, hold),
        _ => bail!("unsupported motion scheme (expected dvrip://)"),
    }
}

/// Each receiver change is stored in MotionDetected and notified to the controllers.
pub fn hook(mut rx: watch::Receiver<bool>, acc: Arc<RwLock<Accessory>>, notifier: Notifier) {
    tokio::spawn(async move {
        while rx.changed().await.is_ok() {
            let on = *rx.borrow_and_update();
            let iid = {
                let mut a = acc.write().unwrap();
                let Some(c) = a
                    .services
                    .iter_mut()
                    .filter(|s| s.ty == u::MOTION_SENSOR)
                    .flat_map(|s| &mut s.chars)
                    .find(|c| c.ty == u::MOTION_DETECTED)
                else {
                    continue;
                };
                c.value = Value::from(on);
                c.iid
            };
            notifier.notify(iid, Value::from(on));
        }
    });
}
