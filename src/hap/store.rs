//! Persistence for the accessory identity and the paired controllers.
//!
//! One file per accessory: `state_dir/<accessory_key>.json`.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow, bail};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use super::crypto::{AccessoryIdentity, Pairings};

/// State store for one accessory, backed by a JSON file.
pub struct FileStore {
    path: PathBuf,
    identity: AccessoryIdentity,
    config_number: u32,
    failed_attempts: u32,
    pairings: Vec<Pairing>,
}

#[derive(Clone)]
struct Pairing {
    id: String,
    ltpk: VerifyingKey,
    admin: bool,
}

/// On-disk format (`<accessory_key>.json`).
#[derive(Serialize, Deserialize)]
struct OnDisk {
    device_id: String,
    /// Ed25519 seed, 32 bytes in hex.
    seed: String,
    config_number: u32,
    /// Failed pair-setup attempts (missing in old files = 0).
    #[serde(default)]
    failed_attempts: u32,
    pairings: Vec<PairingOnDisk>,
}

#[derive(Serialize, Deserialize)]
struct PairingOnDisk {
    id: String,
    /// Ed25519 public key (LTPK), 32 bytes in hex.
    ltpk: String,
    admin: bool,
}

impl FileStore {
    /// Opens (or creates) the state for `accessory_key` inside `state_dir`.
    /// If the file exists but cannot be parsed, it is backed up as `.json.bak` and started fresh.
    pub fn open(state_dir: &Path, accessory_key: &str) -> Result<FileStore> {
        if accessory_key.contains(['/', '\\']) || accessory_key.contains("..") {
            bail!("invalid accessory_key: {accessory_key:?}");
        }
        ensure_private_dir(state_dir)?;
        let path = state_dir.join(format!("{accessory_key}.json"));

        match fs::read(&path) {
            Ok(bytes) => match parse(&bytes, &path) {
                Ok(store) => return Ok(store),
                Err(err) => {
                    let bak = state_dir.join(format!("{accessory_key}.json.bak"));
                    fs::rename(&path, &bak)?;
                    tracing::warn!(
                        "corrupt state at {} ({err}); backed up to {} and reset",
                        path.display(),
                        bak.display()
                    );
                }
            },
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(err.into()),
        }
        let store = FileStore::fresh(path)?;
        store.persist()?;
        Ok(store)
    }

    pub fn identity(&self) -> &AccessoryIdentity {
        &self.identity
    }

    pub fn list(&self) -> Vec<(String, VerifyingKey, bool)> {
        self.pairings
            .iter()
            .map(|p| (p.id.clone(), p.ltpk, p.admin))
            .collect()
    }

    pub fn remove(&mut self, id: &str) -> Result<()> {
        let next: Vec<Pairing> = self
            .pairings
            .iter()
            .filter(|p| p.id != id)
            .cloned()
            .collect();
        self.write_state(self.config_number, &next)?;
        self.pairings = next;
        Ok(())
    }

    pub fn failed_attempts(&self) -> u32 {
        self.failed_attempts
    }

    /// Sets and persists the failed pair-setup attempt counter.
    pub fn set_failed_attempts(&mut self, n: u32) -> Result<()> {
        let prev = std::mem::replace(&mut self.failed_attempts, n);
        if let Err(e) = self.persist() {
            self.failed_attempts = prev;
            return Err(e);
        }
        Ok(())
    }

    /// Removes all pairings (when the last admin is removed).
    pub fn clear_pairings(&mut self) -> Result<()> {
        self.write_state(self.config_number, &[])?;
        self.pairings.clear();
        Ok(())
    }

    /// Increments `config_number` (`c#`) and persists it; returns the new value.
    pub fn bump_config_number(&mut self) -> Result<u32> {
        let next = self
            .config_number
            .checked_add(1)
            .ok_or_else(|| anyhow!("config_number overflows u32"))?;
        self.write_state(next, &self.pairings)?;
        self.config_number = next;
        Ok(next)
    }

    fn fresh(path: PathBuf) -> Result<FileStore> {
        let device_id = random_device_id();
        let seed: [u8; 32] = rand::random();
        Ok(FileStore {
            path,
            identity: AccessoryIdentity {
                device_id,
                signing: SigningKey::from_bytes(&seed),
            },
            config_number: 1,
            failed_attempts: 0,
            pairings: Vec::new(),
        })
    }

    fn persist(&self) -> Result<()> {
        self.write_state(self.config_number, &self.pairings)
    }

    /// Writes the full state to disk. Called before committing an in-memory change.
    fn write_state(&self, config_number: u32, pairings: &[Pairing]) -> Result<()> {
        let on_disk = OnDisk {
            device_id: self.identity.device_id.clone(),
            seed: hex::encode(self.identity.signing.to_bytes()),
            config_number,
            failed_attempts: self.failed_attempts,
            pairings: pairings
                .iter()
                .map(|p| PairingOnDisk {
                    id: p.id.clone(),
                    ltpk: hex::encode(p.ltpk.to_bytes()),
                    admin: p.admin,
                })
                .collect(),
        };
        let json = serde_json::to_vec_pretty(&on_disk)?;
        write_private_atomic(&self.path, &json)
    }
}

impl Pairings for FileStore {
    fn get(&self, id: &str) -> Option<VerifyingKey> {
        self.pairings.iter().find(|p| p.id == id).map(|p| p.ltpk)
    }

    fn add(&mut self, id: String, ltpk: VerifyingKey, admin: bool) -> Result<()> {
        let mut next = self.pairings.clone();
        match next.iter_mut().find(|p| p.id == id) {
            Some(existing) => {
                existing.ltpk = ltpk;
                existing.admin = admin;
            }
            None => next.push(Pairing { id, ltpk, admin }),
        }
        self.write_state(self.config_number, &next)?;
        self.pairings = next;
        Ok(())
    }

    fn is_empty(&self) -> bool {
        self.pairings.is_empty()
    }
}

fn parse(bytes: &[u8], path: &Path) -> Result<FileStore> {
    let on_disk: OnDisk = serde_json::from_slice(bytes)?;
    let seed: [u8; 32] = hex::decode(&on_disk.seed)?
        .try_into()
        .map_err(|_| anyhow!("seed length is not 32 bytes"))?;
    let pairings = on_disk
        .pairings
        .into_iter()
        .map(|p| {
            let bytes: [u8; 32] = hex::decode(&p.ltpk)?
                .try_into()
                .map_err(|_| anyhow!("ltpk length is not 32 bytes"))?;
            Ok(Pairing {
                id: p.id,
                ltpk: VerifyingKey::from_bytes(&bytes)?,
                admin: p.admin,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(FileStore {
        path: path.to_path_buf(),
        identity: AccessoryIdentity {
            device_id: on_disk.device_id,
            signing: SigningKey::from_bytes(&seed),
        },
        config_number: on_disk.config_number,
        failed_attempts: on_disk.failed_attempts,
        pairings,
    })
}

/// 6 random bytes in uppercase hex, separated by `:`.
fn random_device_id() -> String {
    let bytes: [u8; 6] = rand::random();
    bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Creates the directory if missing (0700) and, on unix, enforces 0700 even if it already exists.
fn ensure_private_dir(dir: &Path) -> Result<()> {
    if !dir.is_dir() {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(dir)?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Writes `<path>.tmp` with 0600 permissions and renames it over `path`.
fn write_private_atomic(path: &Path, data: &[u8]) -> Result<()> {
    let mut tmp_name = path.as_os_str().to_owned();
    tmp_name.push(".tmp");
    let tmp = PathBuf::from(tmp_name);
    let _ = fs::remove_file(&tmp);
    {
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut file = opts.open(&tmp)?;
        file.write_all(data)?;
        file.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pk() -> VerifyingKey {
        SigningKey::from_bytes(&rand::random()).verifying_key()
    }

    #[test]
    fn creates_identity_once() {
        let dir = tempfile::tempdir().unwrap();
        let a = FileStore::open(dir.path(), "balcony").unwrap();
        let b = FileStore::open(dir.path(), "balcony").unwrap();
        assert_eq!(a.identity().device_id, b.identity().device_id);
        assert_eq!(
            a.identity().signing.verifying_key(),
            b.identity().signing.verifying_key()
        );
        assert_eq!(a.config_number, 1);
    }

    #[test]
    fn identity_keyed_by_name() {
        let dir = tempfile::tempdir().unwrap();
        let balcony = FileStore::open(dir.path(), "balcony").unwrap();
        let garden = FileStore::open(dir.path(), "garden").unwrap();
        assert_ne!(balcony.identity().device_id, garden.identity().device_id);
        assert!(dir.path().join("balcony.json").exists());
        assert!(dir.path().join("garden.json").exists());
    }

    #[test]
    fn corrupt_file_is_backed_up() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("balcony.json");
        std::fs::write(&file, b"garbage not json").unwrap();
        let store = FileStore::open(dir.path(), "balcony").unwrap();
        assert!(store.is_empty());
        let bak = dir.path().join("balcony.json.bak");
        assert_eq!(std::fs::read(&bak).unwrap(), b"garbage not json");
        // The new state is persisted and readable.
        let again = FileStore::open(dir.path(), "balcony").unwrap();
        assert_eq!(again.identity().device_id, store.identity().device_id);
    }

    #[test]
    fn non_utf8_corrupt_file_is_backed_up() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("balcony.json"), [0xff, 0xfe]).unwrap();
        let store = FileStore::open(dir.path(), "balcony").unwrap();
        assert!(store.is_empty());
        let bak = dir.path().join("balcony.json.bak");
        assert_eq!(std::fs::read(&bak).unwrap(), [0xff, 0xfe]);
    }

    #[test]
    fn rejects_unsafe_accessory_key() {
        let dir = tempfile::tempdir().unwrap();
        for key in ["../x", "a/b", "a\\b", "..", "x..y"] {
            assert!(FileStore::open(dir.path(), key).is_err(), "{key}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn permissions_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("state");
        let _store = FileStore::open(&state, "balcony").unwrap();
        let dir_mode = std::fs::metadata(&state).unwrap().permissions().mode();
        let file_mode = std::fs::metadata(state.join("balcony.json"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(dir_mode & 0o777, 0o700);
        assert_eq!(file_mode & 0o777, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn existing_state_dir_is_made_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let _store = FileStore::open(dir.path(), "balcony").unwrap();
        let mode = std::fs::metadata(dir.path()).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700);
    }

    #[test]
    fn persist_add_remove() {
        let dir = tempfile::tempdir().unwrap();
        let ctl = "11:22:33:44:55:66";
        {
            let mut store = FileStore::open(dir.path(), "balcony").unwrap();
            assert!(store.get(ctl).is_none());
            store.add(ctl.into(), pk(), true).unwrap();
            assert!(store.get(ctl).is_some());
        }
        let mut store = FileStore::open(dir.path(), "balcony").unwrap();
        assert!(store.get(ctl).is_some());
        assert_eq!(store.list().len(), 1);
        assert!(store.list()[0].2);
        store.remove(ctl).unwrap();
        store.remove("does-not-exist").unwrap();
        drop(store);
        let store = FileStore::open(dir.path(), "balcony").unwrap();
        assert!(store.get(ctl).is_none());
        assert!(store.is_empty());
    }

    #[test]
    fn failed_persist_does_not_change_memory() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = FileStore::open(dir.path(), "balcony").unwrap();
        store.add("AA".into(), pk(), false).unwrap();
        // A directory at the temp path makes the write fail.
        std::fs::create_dir(dir.path().join("balcony.json.tmp")).unwrap();
        assert!(store.add("BB".into(), pk(), true).is_err());
        assert!(store.get("BB").is_none());
        assert!(store.remove("AA").is_err());
        assert!(store.get("AA").is_some());
        assert!(store.bump_config_number().is_err());
        assert_eq!(store.config_number, 1);
    }

    #[test]
    fn add_existing_updates_ltpk_and_admin() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = FileStore::open(dir.path(), "balcony").unwrap();
        let (k1, k2) = (pk(), pk());
        store.add("AA".into(), k1, false).unwrap();
        store.add("AA".into(), k2, true).unwrap();
        assert_eq!(store.list(), vec![("AA".to_string(), k2, true)]);
    }

    #[test]
    fn failed_attempts_persist_and_default() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = FileStore::open(dir.path(), "cam").unwrap();
        store.set_failed_attempts(7).unwrap();
        assert_eq!(
            FileStore::open(dir.path(), "cam")
                .unwrap()
                .failed_attempts(),
            7
        );
        // old file without the field
        let path = dir.path().join("cam.json");
        let mut v: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        v.as_object_mut().unwrap().remove("failed_attempts");
        fs::write(&path, v.to_string()).unwrap();
        assert_eq!(
            FileStore::open(dir.path(), "cam")
                .unwrap()
                .failed_attempts(),
            0
        );
    }

    #[test]
    fn bump_config_number_persists() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = FileStore::open(dir.path(), "balcony").unwrap();
        assert_eq!(store.bump_config_number().unwrap(), 2);
        let store = FileStore::open(dir.path(), "balcony").unwrap();
        assert_eq!(store.config_number, 2);
    }
}
