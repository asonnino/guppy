use criterion::{black_box, criterion_group, criterion_main, Criterion};
use minnow_lib::{
    checkpoint_commitment::{CommitmentStrategy, HashCommitment, StandardHashCommitment, MerkleCommitment},
    utils::Digest,
    *,
};

fn benchmark_commitments(c: &mut Criterion) {
    let sizes = [10, 100, 1000, 10000];
    
    for size in sizes {
        let updates = CheckpointUpdates::from(vec![StreamPoint::random(); size]);
        let prev_head = Digest::ZERO;

        let merkle_batch_sizes = [2usize.pow(10), 2usize.pow(15)];
        for batch_size in merkle_batch_sizes {
            c.bench_function(&format!("merkle_commitment_{}_{}", size, batch_size), |b| {
                b.iter(|| MerkleCommitment.commit(black_box(&updates), black_box(&prev_head), batch_size))
            });
        }

        c.bench_function(&format!("hash_commitment_{}", size), |b| {
            b.iter(|| HashCommitment.commit(black_box(&updates), black_box(&prev_head), 100))
        });

        c.bench_function(&format!("standard_hash_commitment_{}", size), |b| {
            b.iter(|| StandardHashCommitment.commit(black_box(&updates), black_box(&prev_head), 100))
        });
    }
}

criterion_group!(benches, benchmark_commitments);
criterion_main!(benches);
