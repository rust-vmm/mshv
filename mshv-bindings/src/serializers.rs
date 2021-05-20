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
