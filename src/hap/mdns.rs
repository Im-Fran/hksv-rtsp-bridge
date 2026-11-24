//! mDNS advertisement (`_hap._tcp.local.`) so iOS can find the accessory.

use anyhow::Result;
use mdns_sd::{IfKind, IfPredicate, ServiceDaemon, ServiceInfo};

const SERVICE_TYPE: &str = "_hap._tcp.local.";

/// HAP TXT records for the advertisement.
pub fn txt(
    name: &str,
    device_id: &str,
    config_number: u32,
    category: u8,
    paired: bool,
) -> Vec<(String, String)> {
    let pair = |k: &str, v: &str| (k.to_string(), v.to_string());
    vec![
        pair("c#", &config_number.to_string()),
        pair("ff", "0"),
        pair("id", device_id),
        pair("md", name),
        pair("pv", "1.1"),
        pair("s#", "1"),
        pair("sf", if paired { "0" } else { "1" }),
        pair("ci", &category.to_string()),
    ]
}

/// Should it re-advertise? Only if the value changed since the last advertisement.
pub fn needs_update(last: &mut bool, now: bool) -> bool {
    std::mem::replace(last, now) != now
}

/// Last 4 hex digits of the device id, without ':'.
fn id_suffix(device_id: &str) -> String {
    let hex: String = device_id.chars().filter(|c| *c != ':').collect();
    hex[hex.len().saturating_sub(4)..].to_string()
}

/// mDNS instance name `"<name> <last 4 hex>"` (HAP-NodeJS convention): each identity
/// has its own instance, so iOS caches don't mix TXT records from old ids.
pub fn instance_name(name: &str, device_id: &str) -> String {
    format!("{name} {}", id_suffix(device_id))
}

/// `<sanitized-name>-<last 4 hex of the id>.local.`
fn hostname(name: &str, device_id: &str) -> String {
    let clean: String = name
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
        .collect();
    format!("{clean}-{}.local.", id_suffix(device_id))
}

/// Keeps the service registered while alive; dropping it unregisters it.
pub struct Advertiser {
    daemon: ServiceDaemon,
    fullname: String,
    name: String,
    device_id: String,
    port: u16,
    category: u8,
}

impl Advertiser {
    pub fn start(
        name: &str,
        device_id: &str,
        port: u16,
        config_number: u32,
        category: u8,
        paired: bool,
    ) -> Result<Advertiser> {
        let daemon = ServiceDaemon::new()?;
        // Loopback is useless on the LAN: avoids advertising 127.0.0.1 / ::1.
        daemon.disable_interface(IfKind::LoopbackV4)?;
        daemon.disable_interface(IfKind::LoopbackV6)?;
        // fe80::1%lo0 does not count as loopback for mdns-sd; it is filtered by name (lo, lo0).
        daemon.disable_interface(IfKind::Predicate(IfPredicate::new(|i| {
            i.name.starts_with("lo")
        })))?;
        let info = service_info(name, device_id, port, config_number, category, paired)?;
        let advertiser = Advertiser {
            daemon,
            fullname: info.get_fullname().to_string(),
            name: name.to_string(),
            device_id: device_id.to_string(),
            port,
            category,
        };
        advertiser.daemon.register(info)?;
        Ok(advertiser)
    }

    /// Re-registers the same service with a new TXT (mdns-sd re-advertises).
    pub fn update(&self, config_number: u32, paired: bool) -> Result<()> {
        let mut info = service_info(
            &self.name,
            &self.device_id,
            self.port,
            config_number,
            self.category,
            paired,
        )?;
        // With probing, mdns-sd does not advertise the new TXT until probing finishes (the old one still
        // lives in the caches); the name was already probed in `start`.
        info.set_requires_probe(false);
        self.daemon.register(info)?;
        Ok(())
    }
}

fn service_info(
    name: &str,
    device_id: &str,
    port: u16,
    config_number: u32,
    category: u8,
    paired: bool,
) -> Result<ServiceInfo> {
    let props = txt(name, device_id, config_number, category, paired);
    let info = ServiceInfo::new(
        SERVICE_TYPE,
        &instance_name(name, device_id),
        &hostname(name, device_id),
        (),
        port,
        props.as_slice(),
    )?
    .enable_addr_auto();
    Ok(info)
}

impl Advertiser {
    /// Sends the goodbye (TTL 0) and shuts down the daemon; waits for confirmation so it isn't cut off.
    pub fn stop(&self) {
        // ponytail: errors ignored on purpose; there is no one to report them to at shutdown.
        if let Ok(rx) = self.daemon.unregister(&self.fullname) {
            let _ = rx.recv_timeout(std::time::Duration::from_millis(500));
        }
        let _ = self.daemon.shutdown();
    }
}

impl Drop for Advertiser {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn txt_records() {
        let expected: Vec<(String, String)> = [
            ("c#", "3"),
            ("ff", "0"),
            ("id", "AA:BB:CC:DD:EE:FF"),
            ("md", "Balcon"),
            ("pv", "1.1"),
            ("s#", "1"),
            ("sf", "1"),
            ("ci", "17"),
        ]
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        assert_eq!(txt("Balcon", "AA:BB:CC:DD:EE:FF", 3, 17, false), expected);
        let paired = txt("Balcon", "AA:BB:CC:DD:EE:FF", 3, 17, true);
        assert!(paired.contains(&("sf".to_string(), "0".to_string())));
    }

    #[test]
    fn instance_and_host_names() {
        assert_eq!(instance_name("Balcón", "AA:BB:CC:DD:6E:5F"), "Balcón 6E5F");
        assert_eq!(hostname("Balcón", "AA:BB:CC:DD:6E:5F"), "Balcn-6E5F.local.");
    }

    #[test]
    fn needs_update_only_on_change() {
        let mut last = false;
        assert!(!needs_update(&mut last, false));
        assert!(needs_update(&mut last, true));
        assert!(!needs_update(&mut last, true));
        assert!(needs_update(&mut last, false));
    }

    /// Live: `cargo test -- --ignored mdns_update_live`.
    #[test]
    #[ignore]
    fn mdns_update_live() {
        let adv = Advertiser::start("MdnsLive", "AA:BB:CC:DD:EE:01", 51991, 1, 17, false).unwrap();
        std::thread::sleep(std::time::Duration::from_secs(3));
        adv.update(2, true).unwrap();
        std::thread::sleep(std::time::Duration::from_secs(1));
        let d = ServiceDaemon::new().unwrap();
        let rx = d.browse(SERVICE_TYPE).unwrap();
        let end = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let mut sf = None;
        while sf.is_none() && std::time::Instant::now() < end {
            if let Ok(mdns_sd::ServiceEvent::ServiceResolved(r)) =
                rx.recv_timeout(std::time::Duration::from_secs(1))
                && r.get_fullname().starts_with("MdnsLive")
            {
                println!("addrs={:?}", r.get_addresses());
                sf = r.get_property_val_str("sf").map(String::from);
            }
        }
        assert_eq!(sf.as_deref(), Some("0"));
    }
}
