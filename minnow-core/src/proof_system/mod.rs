// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

// #[cfg(test)]
// mod fake;
// #[cfg(test)]
// pub use fake::*;

// #[cfg(not(test))]
// mod minnow_mt;
// #[cfg(not(test))]
// pub use minnow_mt::*;

mod fake;
mod minnow_mt;
pub use fake::*;
