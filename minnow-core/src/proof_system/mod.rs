// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "fake")]
mod fake;
#[cfg(feature = "fake")]
pub use fake::*;

#[cfg(not(feature = "fake"))]
mod minnow_mt;
#[cfg(not(feature = "fake"))]
pub use minnow_mt::*;
