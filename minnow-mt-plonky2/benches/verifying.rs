//! Client-side verification cost (the paper's verifyState, minus the committee
//! signature check, which every light client of the chain already performs).
//!
//! Benchmarks: (1) verifying a Minnow-A (one-step) recursive proof at 2^30 streams
//! with 800 updates per proof (degree 16, the configuration quoted in the paper);
//! (2) verifying a Minnow-B cyclic proof in the special configuration
//! (2^30 streams, b = 50, y = 200, alpha = 3); (3) checking one Merkle path of a
//! 2^30 tree. Proofs are measured both uncompressed and compressed (Plonky2
//! `compress`, bincode-serialized as in src/main.rs, which produced the proof
//! size the paper quotes); a client would receive the compressed proof.
//!
//! Run: cargo bench -p minnow-mt-plonky2 --bench verifying

use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};
use hashbrown::HashMap;
use minnow_lib::utils::{generate_sample_updates, F};
use minnow_lib::StreamPoint;
use minnow_mt_plonky2::merkle::MerkleTree;
use minnow_mt_plonky2::one_step_circuit::MinnowMTOneStepCircuit;
use minnow_mt_plonky2::three_step_circuit::{MinnowBCircuits, MinnowBConfig, Orchestrator};
use minnow_mt_plonky2::{MinnowMTServiceState, DEFAULT_BATCH_SIZE, DEFAULT_LOG_STATE_SIZE};
use plonky2::recursion::dummy_circuit::cyclic_base_proof;

fn bench_minnow_a(c: &mut Criterion) {
    let log_state_size = DEFAULT_LOG_STATE_SIZE;
    let batch_size = DEFAULT_BATCH_SIZE;
    let num_batches = 800 / batch_size;
    let circuit = MinnowMTOneStepCircuit::new(log_state_size, num_batches, batch_size, None);
    let verifier_data = &circuit.circuit_data.verifier_only;
    let common_data = &circuit.circuit_data.common;
    println!(
        "minnow-a: degree_bits = {}, gates = {}",
        common_data.degree_bits(),
        circuit.circuit_info.num_gates
    );

    // Two recursive steps, so the measured proof verifies a real previous proof.
    let mut state = MinnowMTServiceState::new(&[], log_state_size);
    let mut proof = cyclic_base_proof(common_data, verifier_data, HashMap::<usize, F>::new());
    let updates = generate_sample_updates(2 * num_batches, batch_size);
    for step in 0..2 {
        let bundle = updates[step * num_batches..(step + 1) * num_batches].to_vec();
        let pw = circuit.apply_bundle_and_compute_witness(
            step,
            &bundle,
            &mut state,
            &proof,
            step == 0,
            verifier_data,
        );
        proof = circuit.circuit_data.prove(pw).unwrap();
    }
    circuit.circuit_data.verify(proof.clone()).unwrap();
    let compressed = circuit.circuit_data.compress(proof.clone()).unwrap();
    circuit.circuit_data.verify_compressed(compressed.clone()).unwrap();
    println!(
        "minnow-a: proof size = {} bytes uncompressed, {} bytes compressed (bincode)",
        proof.to_bytes().len(),
        bincode::serialize(&compressed).unwrap().len()
    );

    c.bench_function("verify_minnow_a_2^30_n800", |b| {
        b.iter_batched(
            || proof.clone(),
            |p| circuit.circuit_data.verify(black_box(p)).unwrap(),
            BatchSize::SmallInput,
        )
    });
    c.bench_function("verify_compressed_minnow_a_2^30_n800", |b| {
        b.iter_batched(
            || compressed.clone(),
            |p| circuit.circuit_data.verify_compressed(black_box(p)).unwrap(),
            BatchSize::SmallInput,
        )
    });
}

fn bench_minnow_b(c: &mut Criterion) {
    // Special configuration: b = 50, 4 batches per sub-bundle (y = 200), alpha = 3.
    // One aggregation level keeps setup short; the cyclic circuit, and hence the
    // client's verification cost, does not depend on the number of levels.
    let config = MinnowBConfig::new(DEFAULT_LOG_STATE_SIZE, DEFAULT_BATCH_SIZE, 4, 3, 1);
    let circuits = MinnowBCircuits::new_with_config(&config);
    println!(
        "minnow-b: cyclic degree_bits = {}, gates = {}",
        circuits.sequential_circuit.circuit_info.degree_bits,
        circuits.sequential_circuit.circuit_info.num_gates
    );
    let mut orchestrator = Orchestrator::new(circuits.build_provers(), false);
    let bundles = config.generate_multiple_sample_bundles(2);
    let mut proof = orchestrator.compute_proof(&bundles[0]);
    proof = {
        let p = orchestrator.compute_proof(&bundles[1]);
        drop(proof);
        p
    };
    orchestrator.verify_cyclic_proof(proof.clone());
    let cyclic_data = &orchestrator.provers.cyclic_prover.cyclic_circuit.circuit_data;
    let compressed = cyclic_data.compress(proof.clone()).unwrap();
    cyclic_data.verify_compressed(compressed.clone()).unwrap();
    println!(
        "minnow-b: cyclic proof size = {} bytes uncompressed, {} bytes compressed (bincode)",
        proof.to_bytes().len(),
        bincode::serialize(&compressed).unwrap().len()
    );
    c.bench_function("verify_compressed_minnow_b_cyclic", |b| {
        b.iter_batched(
            || compressed.clone(),
            |p| cyclic_data.verify_compressed(black_box(p)).unwrap(),
            BatchSize::SmallInput,
        )
    });

    c.bench_function("verify_minnow_b_cyclic", |b| {
        b.iter_batched(
            || proof.clone(),
            |p| orchestrator.verify_cyclic_proof(black_box(p)),
            BatchSize::SmallInput,
        )
    });
}

fn bench_merkle_path(c: &mut Criterion) {
    let points: Vec<StreamPoint> = (0..1024).map(|_| StreamPoint::random()).collect();
    let tree = MerkleTree::build_from_stream_points(&points, DEFAULT_LOG_STATE_SIZE + 1);
    let root = tree.root();
    let index = 517;
    let path = tree.get_proof(index).unwrap();
    assert!(path.verify_proof(&root, &points[index], index));

    c.bench_function("verify_merkle_path_2^30", |b| {
        b.iter(|| path.verify_proof(black_box(&root), black_box(&points[index]), index))
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(50);
    targets = bench_merkle_path, bench_minnow_a, bench_minnow_b
}
criterion_main!(benches);
