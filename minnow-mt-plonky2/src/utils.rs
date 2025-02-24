use plonky2::gates::noop::NoopGate;
use plonky2::iop::witness::PartialWitness;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::circuit_data::CommonCircuitData;
use plonky2::plonk::config::Hasher;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

use log::info;

use crate::{CheckpointUpdates, StreamPoint};

pub fn init_logging(level: log::LevelFilter) {
    // Initialize logging
    let mut builder = env_logger::Builder::from_default_env();
    builder.format_timestamp(None);
    builder.filter_level(level);
    builder.try_init().unwrap();
}

pub fn print_system_info(num_levels: usize, num_checkpoint_updates: usize) {
    info!(
        "Max Merkle tree levels: {} ({} elements)",
        num_levels,
        1 << (num_levels - 1)
    );
    info!(
        "Number of checkpoint updates (fixed): {}",
        num_checkpoint_updates
    );
}

// Test vector: All checkpoints update the same set of stream points
pub fn generate_sample_checkpoint_updates(
    num_checkpoints: usize,
    num_checkpoint_updates: usize,
) -> Vec<CheckpointUpdates> {
    let start_checkpoint_number = 0;
    let mut all_updates = Vec::new();
    let first_set = (0..num_checkpoint_updates)
        .map(|i| {
            StreamPoint::new_with_flag(
                i.try_into().unwrap(),
                [start_checkpoint_number as u8; 32],
                true,
            )
        })
        .collect();
    all_updates.push(first_set);
    for _ in 1..num_checkpoints {
        all_updates.push(
            (0..num_checkpoint_updates)
                .map(|i| {
                    StreamPoint::new_with_flag(
                        i.try_into().unwrap(),
                        [(start_checkpoint_number + i) as u8; 32],
                        false,
                    )
                })
                .collect(),
        );
    }
    all_updates
}

// Plonky2 utils begin
pub const D: usize = 2;
pub type C = PoseidonGoldilocksConfig;
pub type F = <C as GenericConfig<D>>::F;
pub type H = <C as GenericConfig<D>>::Hasher;
pub type Digest = <H as Hasher<F>>::Hash;
pub type InnerHasher = <C as GenericConfig<D>>::InnerHasher;
pub type MyCircuitBuilder = CircuitBuilder<F, D>;
pub type MyPartialWitness = PartialWitness<F>;

// Generates `CommonCircuitData` usable for recursion.
pub fn common_data_for_recursion(
    expected_degree_bits: usize,
    num_public_inputs: usize,
) -> CommonCircuitData<F, D> {
    let config = CircuitConfig::standard_recursion_config();
    let builder = CircuitBuilder::<F, D>::new(config);
    let data = builder.build::<C>();

    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    let proof = builder.add_virtual_proof_with_pis(&data.common);
    let verifier_data = builder.add_virtual_verifier_data(data.common.config.fri_config.cap_height);
    builder.verify_proof::<C>(&proof, &verifier_data, &data.common);
    let data = builder.build::<C>();

    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    let proof = builder.add_virtual_proof_with_pis(&data.common);
    let verifier_data = builder.add_virtual_verifier_data(data.common.config.fri_config.cap_height);
    builder.verify_proof::<C>(&proof, &verifier_data, &data.common);

    // Add noop gates until we reach the expected degree bits.
    //  We end the loop when num_gates reaches (1 << (expected_degree_bits - 1)) + 1.
    //  Padding takes care of the rest to ensure that the final gate count is 1 << expected_degree_bits.
    while builder.num_gates() < 1 << (expected_degree_bits - 1) {
        builder.add_gate(NoopGate, vec![]);
    }

    // Build the circuit
    let mut common_data = builder.build::<C>().common;
    assert_eq!(common_data.degree_bits(), expected_degree_bits);
    common_data.num_public_inputs = num_public_inputs;
    common_data
}

mod test {
    use super::*;

    #[test]
    fn test_common_data_for_recursion_basic() {
        // init_logging(LevelFilter::Debug);
        let expected_degree_bits = 14;
        let num_public_inputs = 10;
        let common_data = common_data_for_recursion(expected_degree_bits, num_public_inputs);
        assert_eq!(common_data.degree_bits(), expected_degree_bits);
    }

    #[test]
    fn test_common_data_for_recursion_full() {
        let expected_degree_bits = 14;
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let _verifier_data_target = builder.add_verifier_data_public_inputs();
        let common_data =
            common_data_for_recursion(expected_degree_bits, builder.num_public_inputs());
        assert_eq!(common_data.degree_bits(), expected_degree_bits);

        let inner_cyclic_proof_with_pis = builder.add_virtual_proof_with_pis(&common_data);
        let condition = builder.add_virtual_bool_target_safe();
        builder
            .conditionally_verify_cyclic_proof_or_dummy::<C>(
                condition,
                &inner_cyclic_proof_with_pis,
                &common_data,
            )
            .unwrap();

        // Doing it twice just to reach the expected gate count.
        builder
            .conditionally_verify_cyclic_proof_or_dummy::<C>(
                condition,
                &inner_cyclic_proof_with_pis,
                &common_data,
            )
            .unwrap();
        builder.print_gate_counts(0);
        builder.build::<C>().common;
    }
}
