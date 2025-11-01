use crate::server::services::types::patterns::MatchDetails;
use chrono::DateTime;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use strum_macros::Display;
use strum_macros::EnumDiscriminants;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, Hash, EnumDiscriminants)]
#[strum_discriminants(derive(Hash, Serialize, Deserialize))]
#[serde(tag = "type")]
pub enum EntitySource {
    Manual,
    System,
    // Used with hosts and subnets
    Discovery {
        metadata: Vec<DiscoveryMetadata>,
    },
    // Only used with services
    DiscoveryWithMatch {
        metadata: Vec<DiscoveryMetadata>,
        details: MatchDetails,
    },
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, Copy, Hash)]
pub struct DiscoveryMetadata {
    #[serde(flatten)]
    pub discovery_type: DiscoveryType,
    pub daemon_id: Uuid,
    pub date: DateTime<Utc>,
}

impl DiscoveryMetadata {
    pub fn new(discovery_type: DiscoveryType, daemon_id: Uuid) -> Self {
        Self {
            discovery_type,
            daemon_id,
            date: Utc::now(),
        }
    }
}

impl Default for DiscoveryMetadata {
    fn default() -> Self {
        Self {
            discovery_type: DiscoveryType::Network,
            daemon_id: Uuid::new_v4(),
            date: Utc::now(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, Hash, Display, Copy)]
#[serde(tag = "discovery_type")]
pub enum DiscoveryType {
    SelfReport,
    Network,
    Ping,
    Docker { host_id: Uuid },
    Proxmox { host_id: Uuid },
}
