use sp1_sdk::include_elf;

use crate::common::ProverEnv;

/// The ELF (executable and linkable format) file for the Succinct RISC-V zkVM.
#[allow(unused)]
pub const MINNOW_MT_ELF: &[u8] = include_elf!("minnow-mt-program");

pub fn run() -> anyhow::Result<ProverEnv<'static>> {
    todo!()
}
