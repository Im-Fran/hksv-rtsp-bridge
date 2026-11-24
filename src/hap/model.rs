//! HAP accessory model (aid, services, characteristics) and its `/accessories` JSON.

use anyhow::Result;
use bitflags::bitflags;
use serde_json::{Value, json};
use uuid::Uuid;

use super::uuids::short;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    Bool,
    U8,
    U16,
    U32,
    U64,
    Int,
    Float,
    String,
    Tlv8,
    Data,
}

impl Format {
    pub fn name(self) -> &'static str {
        match self {
            Format::Bool => "bool",
            Format::U8 => "uint8",
            Format::U16 => "uint16",
            Format::U32 => "uint32",
            Format::U64 => "uint64",
            Format::Int => "int",
            Format::Float => "float",
            Format::String => "string",
            Format::Tlv8 => "tlv8",
            Format::Data => "data",
        }
    }
}

bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Perms: u8 {
        const PR = 1;
        const PW = 2;
        const EV = 4;
        const TW = 8;
        const WR = 16;
        const AA = 32;
    }
}

impl Perms {
    fn names(self) -> Vec<&'static str> {
        [
            (Perms::PR, "pr"),
            (Perms::PW, "pw"),
            (Perms::EV, "ev"),
            (Perms::TW, "tw"),
            (Perms::WR, "wr"),
            (Perms::AA, "aa"),
        ]
        .into_iter()
        .filter(|(p, _)| self.contains(*p))
        .map(|(_, n)| n)
        .collect()
    }
}

#[derive(Clone, Debug)]
pub struct Characteristic {
    pub iid: u64,
    pub ty: Uuid,
    pub format: Format,
    pub perms: Perms,
    /// TLV8/Data values are sent as base64 strings.
    pub value: Value,
}

#[derive(Clone, Debug)]
pub struct Service {
    pub iid: u64,
    pub ty: Uuid,
    pub primary: bool,
    pub hidden: bool,
    /// iids of linked services (`linked` in the accessory JSON).
    pub linked: Vec<u64>,
    pub chars: Vec<Characteristic>,
}

#[derive(Clone, Debug)]
pub struct Accessory {
    /// Always 1.
    pub aid: u64,
    pub services: Vec<Service>,
}

impl Accessory {
    pub fn find(&self, iid: u64) -> Option<&Characteristic> {
        self.services
            .iter()
            .flat_map(|s| &s.chars)
            .find(|c| c.iid == iid)
    }

    pub fn find_mut(&mut self, iid: u64) -> Option<&mut Characteristic> {
        self.services
            .iter_mut()
            .flat_map(|s| &mut s.chars)
            .find(|c| c.iid == iid)
    }

    pub fn to_json(&self) -> Value {
        let services: Vec<Value> = self
            .services
            .iter()
            .map(|s| {
                let mut o = json!({"iid": s.iid, "type": short(&s.ty),
                    "characteristics": s.chars.iter().map(Characteristic::to_json).collect::<Vec<_>>()});
                if s.primary {
                    o["primary"] = true.into();
                }
                if s.hidden {
                    o["hidden"] = true.into();
                }
                if !s.linked.is_empty() {
                    o["linked"] = json!(s.linked);
                }
                o
            })
            .collect();
        json!({"accessories": [{"aid": self.aid, "services": services}]})
    }
}

impl Characteristic {
    pub fn to_json(&self) -> Value {
        let mut o = json!({"iid": self.iid, "type": short(&self.ty),
            "perms": self.perms.names(), "format": self.format.name()});
        if self.perms.contains(Perms::PR) {
            o["value"] = self.value.clone();
        }
        o
    }
}

pub struct ResourceRequest {
    pub width: u32,
    pub height: u32,
}

/// Accessory logic: reading/writing characteristics and snapshots.
#[async_trait::async_trait]
pub trait Handler: Send + Sync {
    async fn read(&self, iid: u64) -> Result<Value>;
    /// `response`: the controller requested a write-response (`"r": true`).
    async fn write(&self, iid: u64, v: Value, response: bool) -> Result<Option<Value>>;
    async fn resource(&self, req: ResourceRequest) -> Result<Vec<u8>>;
}
