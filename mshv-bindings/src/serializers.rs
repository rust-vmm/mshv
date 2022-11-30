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
        let data_buffer: Vec<::std::os::raw::c_char> = Vec::deserialize(deserializer)?;
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
#[cfg(test)]
mod tests {
    use super::*;
    use random_number::random;
    use std::ptr;

    #[test]
    fn test_lapic_state_serialization_deserialization() {
        let mut state = LapicState::default();
        let mut n1: u8 = random!();
        for i in 0..1024 {
            state.regs[i] = n1 as ::std::os::raw::c_char;
            n1 = random!();
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
        let flags: u64 = 0x12345678;
        let states: u64 = 0x87654321;
        let data_size: u64 = 4096;

        let mut n1: u8 = random!();
        for i in 0..4096 {
            xsave.buffer[i + 24] = n1 as ::std::os::raw::c_char;
            n1 = random!();
        }
        let mut _bs = flags.to_le_bytes();
        // SAFETY: We construct the buffer same way as we retrieve it
        unsafe {
            ptr::copy(
                _bs.as_ptr() as *mut u8,
                xsave.buffer.as_ptr().offset(0) as *mut u8,
                8,
            )
        };
        _bs = states.to_le_bytes();
        // SAFETY: We construct the buffer same way as we retrieve it
        unsafe {
            ptr::copy(
                _bs.as_ptr() as *mut u8,
                xsave.buffer.as_ptr().offset(8) as *mut u8,
                8,
            )
        };
        _bs = data_size.to_le_bytes();
        // SAFETY: We construct the buffer same way as we retrieve it
        unsafe {
            ptr::copy(
                _bs.as_ptr() as *mut u8,
                xsave.buffer.as_ptr().offset(16) as *mut u8,
                8,
            )
        };
        let serialized = serde_json::to_string(&xsave).expect("err ser");
        let d_xsave: XSave = serde_json::from_str(&serialized).expect("err unser");
        assert!(xsave.flags() == d_xsave.flags());
        assert!(xsave.states() == d_xsave.states());
        assert!(xsave.data_size() == d_xsave.data_size());
        assert!(xsave
            .buffer
            .iter()
            .zip(d_xsave.buffer.iter())
            .all(|(a, b)| a == b));
    }
}
