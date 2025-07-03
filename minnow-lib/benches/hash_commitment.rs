use criterion::{black_box, criterion_group, criterion_main, Criterion};
use minnow_lib::hash_commitment_parallel;
use minnow_lib::utils::{generate_random_batches, Digest};

fn bench_hash_commitment_varying_batch_sizes(c: &mut Criterion) {
    let mut group = c.benchmark_group("hash_commitment_varying_batch_sizes");
    for total_num_updates in [2_u64.pow(11), 2_u64.pow(12), 2_u64.pow(13)] {
        for batch_size in [2, 8, 32, 128, 512, 2048] {
            let num_batches = total_num_updates / batch_size as u64;
            assert!(num_batches * batch_size == total_num_updates);
            let updates = generate_random_batches(num_batches as usize, batch_size as usize);
            let prev_head = Digest::ZERO;

            group.bench_function(
                &format!("updates_{}_batch_size_{}", total_num_updates, batch_size),
                |b| {
                    b.iter(|| {
                        hash_commitment_parallel(black_box(&updates), black_box(batch_size as usize), black_box(&prev_head), None)
                    })
                },
            );
        }
    }
    group.finish();
}

fn bench_hash_commitment_varying_num_batches(c: &mut Criterion) {
    let mut group = c.benchmark_group("hash_commitment_varying_num_batches");

    for num_batches in [1, 2, 4, 8, 16, 32, 64, 128] {
        let batch_size = 50; // 50 * 64 = 3200
        let updates = generate_random_batches(num_batches, batch_size);
        let prev_head = Digest::ZERO;

        // group.bench_function(
        //     &format!("sequential_num_batches_{}", num_batches),
        //     |b| {
        //         b.iter(|| {
        //             hash_commitment(black_box(&updates), black_box(batch_size), black_box(&prev_head))
        //         })
        //     },
        // );

        group.bench_function(
            &format!("parallel_num_batches_{}", num_batches),
            |b| {
                b.iter(|| {
                    hash_commitment_parallel(black_box(&updates), black_box(batch_size), black_box(&prev_head), black_box(None))
                })
            },
        );
    }
    group.finish();
}

fn bench_hash_commitment_thread_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("hash_commitment_thread_scaling");
    
    let updates = generate_random_batches(100, 50);
    let batch_size = 50;
    let prev_head = Digest::ZERO;

    // Test with different thread counts
    for thread_count in [1, 2, 4, 8] {
        group.bench_function(
            &format!("parallel_{}_threads", thread_count),
            |b| {
                b.iter(|| {
                    hash_commitment_parallel(
                        black_box(&updates), 
                        black_box(batch_size), 
                        black_box(&prev_head),
                        black_box(Some(thread_count))
                    )
                })
            },
        );
    }

    // Also test the unlimited version for comparison
    group.bench_function("parallel_unlimited_threads", |b| {
        b.iter(|| {
            hash_commitment_parallel(black_box(&updates), black_box(batch_size), black_box(&prev_head), None)
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_hash_commitment_varying_batch_sizes,
    bench_hash_commitment_varying_num_batches,
    bench_hash_commitment_thread_scaling
);
criterion_main!(benches); 