//! CIGL configuration and nested-interaction authorization. A trace describes
//! execution; it never supplies a grant, activation or root-method permission.
use pc_runtime_types::{RuntimeError, RuntimeResult};
use serde::{Deserialize, Serialize};

pub mod analysis;
pub mod grants;
pub mod profile;
pub mod program;
pub mod settings;

#[cfg(test)]
mod method_tests;

/// UF-CIGL-001 / CIGL-C07. Frame count includes the root; nested depth starts
/// at zero for the root. Transport and request deadlines may narrow these caps.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TraceLimits {
    pub max_depth: u16,
    pub max_frames: u16,
    pub max_response_bytes: u32,
    pub timeout_ms: u32,
}
impl TraceLimits {
    pub fn validate(&self) -> RuntimeResult<()> {
        if !(1..=128).contains(&self.max_depth)
            || !(1..=2048).contains(&self.max_frames)
            || !(100_000..=20_000_000).contains(&self.max_response_bytes)
            || !(500..=30_000).contains(&self.timeout_ms)
        {
            return Err(RuntimeError::InvalidInput);
        }
        Ok(())
    }

    pub fn json_depth(&self) -> RuntimeResult<u32> {
        self.validate()?;
        Ok(u32::from(self.max_depth) * 2 + 4)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CallKind {
    Call,
    Staticcall,
    Delegatecall,
    Callcode,
    Create,
    Create2,
    Selfdestruct,
}
impl CallKind {
    pub fn transfers_value(self) -> bool {
        matches!(
            self,
            Self::Call | Self::Create | Self::Create2 | Self::Selfdestruct
        )
    }
}
