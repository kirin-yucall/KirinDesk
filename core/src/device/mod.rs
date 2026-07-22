use serde::{Deserialize, Serialize};

/// Device identity information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceId {
    pub id: String,
}

impl DeviceId {
    pub fn new(id: impl Into<String>) -> Self {
        Self { id: id.into() }
    }
}
