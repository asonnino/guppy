use criterion::{black_box, criterion_group, criterion_main, Criterion};
use minnow_lib::utils::{generate_sample_updates, Digest};
use minnow_mt_plonky2::{two_step_circuit::BaseCircuit, MinnowMTServiceState};
use std::collections::HashMap;

// The goal is to benchmark plonky2 proving times for different circuit sizes.
// We will use the two_step_circuit.rs's base circuit.

fn find_configs() -> Vec<(usize, (usize, usize, BaseCircuit))> {
    let log_state_sizes = 10;
    let step = 100;
    let mut configs = HashMap::new();
    for num_checkpoint_updates in (100..=1000).step_by(step) {
        let circuit = BaseCircuit::new(log_state_sizes, num_checkpoint_updates);
        // Insert the config if it is not already in the map.
        if !configs.contains_key(&circuit.circuit_info.degree_bits) {
            configs.insert(
                circuit.circuit_info.degree_bits,
                (log_state_sizes, num_checkpoint_updates, circuit),
            );
        }
    }
    // Ensure that there is at least one config for each degree bit from 12 to 15.
    // TODO: Expand range
    for degree_bit in 12..=15 {
        assert!(configs.contains_key(&degree_bit));
    }

    // Return a sorted list of configs by degree bits.
    let mut configs_list: Vec<_> = configs.into_iter().collect();
    configs_list.sort_by_key(|(degree_bits, _)| *degree_bits);
    configs_list
}

fn bench_prover(c: &mut Criterion) {
    let configs = find_configs();
    for (degree, (log_state_size, num_checkpoint_updates, circuit)) in configs {
        println!(
            "Degree bits: {:?}, log_state_size: {:?}, num_checkpoint_updates: {:?}",
            degree, log_state_size, num_checkpoint_updates
        );
        let mut zk_service_state = MinnowMTServiceState::new(&[], log_state_size);
        let all_checkpoint_updates = generate_sample_updates(1, num_checkpoint_updates);
        let old_head = Digest::ZERO;
        let pw = circuit.apply_checkpoint_updates_and_set_inputs(
            &all_checkpoint_updates[0],
            &mut zk_service_state,
            &old_head,
        );

        c.bench_function(format!("circuit_{}", degree).as_str(), |b| {
            b.iter(|| {
                let _proof = circuit.circuit_data.prove(black_box(pw.clone()));
            })
        });
    }
}

criterion_group!(benches, bench_prover);
criterion_main!(benches);
