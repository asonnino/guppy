// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::fmt::{Debug, Display};

use serde::{Deserialize, Serialize};

use crate::{protocol::ProtocolParameters, settings::Settings, Config};

/// Shortcut avoiding to use the generic version of the benchmark parameters.
pub type BenchmarkParameters = BenchmarkParametersGeneric<Config>;

/// The benchmark parameters for a run. These parameters are stored along with the performance data
/// and should be used to reproduce the results.
#[derive(Serialize, Deserialize, Clone)]
pub struct BenchmarkParametersGeneric<N> {
    /// The testbed settings.
    pub settings: Settings,
    /// The target's configuration parameters.
    pub target_configs: N,
}

impl<N: Debug> Debug for BenchmarkParametersGeneric<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.target_configs)
    }
}

impl<N: Display> Display for BenchmarkParametersGeneric<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[todo, summary config]")
    }
}

impl<N: ProtocolParameters> BenchmarkParametersGeneric<N> {
    /// Make a new benchmark parameters.
    pub fn new(settings: Settings, target_configs: N) -> Self {
        Self {
            settings,
            target_configs,
        }
    }

    #[cfg(test)]
    pub fn new_for_test() -> Self {
        Self {
            settings: Settings::new_for_test(),
            target_configs: N::default(),
        }
    }
}

#[cfg(test)]
pub mod test {
    use std::{fmt::Display, str::FromStr};

    use serde::{Deserialize, Serialize};

    use super::ProtocolParameters;

    /// Mock benchmark type for unit tests.
    #[derive(
        Serialize, Deserialize, Debug, Clone, PartialEq, PartialOrd, Eq, Ord, Hash, Default,
    )]
    pub struct TestConfig;

    impl Display for TestConfig {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "TestNodeConfig")
        }
    }

    impl FromStr for TestConfig {
        type Err = ();

        fn from_str(_s: &str) -> Result<Self, Self::Err> {
            Ok(Self {})
        }
    }

    impl ProtocolParameters for TestConfig {}
}
