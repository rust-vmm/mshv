// Copyright © 2020, Microsoft Corporation
//
// SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause
//
use vmm_sys_util::errno;
pub mod vcpu;
/// A specialized `Result` type for MSHV ioctls.
///
/// This typedef is generally used to avoid writing out errno::Error directly and
/// is otherwise a direct mapping to Result.
pub type Result<T> = std::result::Result<T, errno::Error>;
