use criterion::{black_box, criterion_group, criterion_main, Criterion};
use minnow_lib::utils::generate_sample_updates;
use minnow_mt_plonky2::{two_step_circuit::BaseCircuit, MinnowMTServiceState};
use std::collections::HashMap;

// The goal is to benchmark plonky2 proving times for different circuit sizes.
// We will use the two_step_circuit.rs's base circuit.

fn find_configs() -> Vec<(usize, (usize, usize, BaseCircuit))> {
    let log_state_sizes = 20;
    let mut configs = HashMap::new();
    for num_checkpoint_updates in [100, 200, 500, 1150, 2450] {
        let circuit = BaseCircuit::new(log_state_sizes, 1, num_checkpoint_updates);
        // Insert the config if it is not already in the map.
        if !configs.contains_key(&circuit.circuit_info.degree_bits) {
            println!("Added config: {:?}", circuit.circuit_info.degree_bits);
            configs.insert(
                circuit.circuit_info.degree_bits,
                (log_state_sizes, num_checkpoint_updates, circuit),
            );
        }
    }
    println!("\n");

    for degree_bit in 13..=17 {
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
        let pw = circuit
            .apply_bundle_and_compute_witness(&all_checkpoint_updates, &mut zk_service_state);

        // Generate a proof once and reuse it for both size calculation and verification
        let proof = circuit
            .circuit_data
            .prove(pw.clone())
            .expect("Failed to generate proof");

        // Calculate and display proof size
        let proof_bytes = bincode::serialize(&proof).expect("Failed to serialize proof");
        let proof_size = proof_bytes.len();
        println!(
            "Proof size: {} bytes ({:.2} KB)",
            proof_size,
            proof_size as f64 / 1024.0
        );

        let compressed_proof = circuit
            .circuit_data
            .compress(proof)
            .expect("Failed to compress proof");
        let compressed_proof_bytes =
            bincode::serialize(&compressed_proof).expect("Failed to serialize compressed proof");
        let compressed_proof_size = compressed_proof_bytes.len();
        println!(
            "Compressed proof size: {} bytes ({:.2} KB)",
            compressed_proof_size,
            compressed_proof_size as f64 / 1024.0
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
