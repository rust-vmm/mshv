// Copyright © 2020, Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//
#![cfg(feature = "with-serde")]

use serde::de::{Deserialize, Deserializer};
use serde::{Serialize, Serializer};

use super::regs::*;

impl<'de> Deserialize<'de> for LapicState {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let regs: Vec<::std::os::raw::c_char> = Vec::deserialize(deserializer)?;
        let mut val = LapicState::default();
        // This panics if the source and destination have different lengths.
        val.regs.copy_from_slice(&regs[..]);
        Ok(val)
    }
}

impl Serialize for LapicState {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let regs = &self.regs[..];
        regs.serialize(serializer)
    }
}
impl<'de> Deserialize<'de> for XSave {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let data_buffer: Vec<u8> = Vec::deserialize(deserializer)?;
        let mut val = XSave::default();
        // This panics if the source and destination have different lengths.
        val.buffer.copy_from_slice(&data_buffer[..]);
        Ok(val)
    }
}

impl Serialize for XSave {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let data_buffer = &self.buffer[..];
        data_buffer.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SynicMessagePage {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let data_buffer: Vec<u8> = Vec::deserialize(deserializer)?;
        let mut val = SynicMessagePage::default();
        // This panics if the source and destination have different lengths.
        val.buffer.copy_from_slice(&data_buffer[..]);
        Ok(val)
    }
}

impl Serialize for SynicMessagePage {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let data_buffer = &self.buffer[..];
        data_buffer.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SynicEventFlagsPage {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let data_buffer: Vec<u8> = Vec::deserialize(deserializer)?;
        let mut val = SynicEventFlagsPage::default();
        // This panics if the source and destination have different lengths.
        val.buffer.copy_from_slice(&data_buffer[..]);
        Ok(val)
    }
}

impl Serialize for SynicEventFlagsPage {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let data_buffer = &self.buffer[..];
        data_buffer.serialize(serializer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use random_number::random;

    #[test]
    fn test_lapic_state_serialization_deserialization() {
        let mut state = LapicState::default();
        for i in 0..1024 {
            state.regs[i] = random!();
        }
        let serialized = serde_json::to_string(&state).expect("err ser");
        let d_state: LapicState = serde_json::from_str(&serialized).expect("err unser");
        assert!(state
            .regs
            .iter()
            .zip(d_state.regs.iter())
            .all(|(a, b)| a == b));
    }

    #[test]
    fn test_xsave_serialization_deserialization() {
        let mut xsave = XSave {
            ..Default::default()
        };
        for i in 0..4096 {
            xsave.buffer[i] = random!();
        }
        let serialized = serde_json::to_string(&xsave).expect("err ser");
        let d_xsave: XSave = serde_json::from_str(&serialized).expect("err unser");
        assert!(xsave
            .buffer
            .iter()
            .zip(d_xsave.buffer.iter())
            .all(|(a, b)| a == b));
    }

    #[test]
    fn test_simp_serialization_deserialization() {
        let mut simp = SynicMessagePage {
            ..Default::default()
        };
        for i in 0..4096 {
            simp.buffer[i] = random!();
        }
        let serialized = serde_json::to_string(&simp).expect("err ser");
        let d_simp: SynicMessagePage = serde_json::from_str(&serialized).expect("err unser");
        assert!(simp
            .buffer
            .iter()
            .zip(d_simp.buffer.iter())
            .all(|(a, b)| a == b));
    }

    #[test]
    fn test_sief_serialization_deserialization() {
        let mut sief = SynicEventFlagsPage {
            ..Default::default()
        };
        for i in 0..4096 {
            sief.buffer[i] = random!();
        }
        let serialized = serde_json::to_string(&sief).expect("err ser");
        let d_sief: SynicEventFlagsPage = serde_json::from_str(&serialized).expect("err unser");
        assert!(sief
            .buffer
            .iter()
            .zip(d_sief.buffer.iter())
            .all(|(a, b)| a == b));
    }
}
