//! Minnow-H microbenchmark: for each (tracked streams m, updates per checkpoint n),
//! build the cyclic circuit, prove a chain of checkpoints, and report the median
//! proving time per checkpoint, the compressed proof size, and the client's
//! verification time. Prints one CSV row per configuration.
//!
//! Run: cargo run --release -p minnow-h-plonky2 -- --tracked 1,4,16,64 --updates 100,1000,2100

use clap::Parser;
use log::{info, LevelFilter};
use minnow_h_plonky2::circuit::MinnowHCircuit;
use minnow_h_plonky2::{tracked_stream_ids, MinnowHServiceState};
use minnow_lib::utils::{generate_random_batches, set_log_level, Digest};
use minnow_lib::{hash_commitment, Batch, StreamID, StreamPoint, STREAM_VAL_LEN};
use std::time::{Duration, Instant};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Numbers of tracked streams (m), comma separated.
    #[arg(long, value_delimiter = ',', default_value = "1,4,16,64")]
    tracked: Vec<usize>,

    /// Updates per checkpoint (n), comma separated; multiples of the batch size.
    #[arg(long, value_delimiter = ',', default_value = "100,1000,2100")]
    updates: Vec<usize>,

    #[arg(long, default_value_t = 50)]
    batch_size: usize,

    /// Recursive proofs timed per configuration (after the base-case proof).
    #[arg(long, default_value_t = 5)]
    runs: usize,

    #[arg(short, long, default_value_t = false)]
    debug: bool,
}

/// Random updates, with every tracked stream updated once.
fn checkpoint(num_batches: usize, batch_size: usize, tracked: &[StreamID], c: usize) -> Vec<Batch> {
    let mut batches = generate_random_batches(num_batches, batch_size);
    let n = num_batches * batch_size;
    for (k, id) in tracked.iter().enumerate() {
        let pos = (k * n) / tracked.len().max(1);
        batches[pos / batch_size][pos % batch_size] =
            StreamPoint::new(*id, [(c + k) as u8; STREAM_VAL_LEN]);
    }
    batches
}

fn median(mut v: Vec<Duration>) -> Duration {
    v.sort();
    v[v.len() / 2]
}

fn main() {
    let args = Args::parse();
    set_log_level(if args.debug { LevelFilter::Debug } else { LevelFilter::Info });
    info!("{:?}", args);

    println!("csv,tracked,updates,batch_size,gates,degree_bits,build_s,prove_ms,proof_bytes_compressed,verify_compressed_ms");
    for &n in &args.updates {
        assert_eq!(n % args.batch_size, 0, "updates must be a multiple of the batch size");
        let num_batches = n / args.batch_size;
        for &m in &args.tracked {
            let tracked = tracked_stream_ids(m);
            let start = Instant::now();
            let circuit = MinnowHCircuit::new(num_batches, args.batch_size, &tracked);
            let build = start.elapsed();
            let data = &circuit.circuit_data;

            let mut state = MinnowHServiceState::new(&tracked);
            let mut head = Digest::ZERO;
            let mut proof = circuit.base_proof();
            let mut prove_times = vec![];
            for c in 0..=args.runs {
                let batches = checkpoint(num_batches, args.batch_size, &tracked, c);
                let start = Instant::now();
                proof = circuit.prove(&batches, &state, &proof, c == 0);
                let elapsed = start.elapsed();
                if c > 0 {
                    prove_times.push(elapsed); // the base case skips the inner verifier
                }
                head = hash_commitment(&batches, args.batch_size, &head).unwrap();
                state.apply_checkpoint_updates(&batches);
                assert_eq!(proof.public_inputs[0..4], head.elements);
                assert_eq!(proof.public_inputs[4..8], state.commit().elements);
            }

            let compressed = data.compress(proof.clone()).unwrap();
            let size = bincode::serialize(&compressed).unwrap().len();
            let mut verify_times = vec![];
            for _ in 0..20 {
                let p = compressed.clone();
                let start = Instant::now();
                data.verify_compressed(p).unwrap();
                verify_times.push(start.elapsed());
            }

            println!(
                "csv,{},{},{},{},{},{:.1},{:.1},{},{:.2}",
                m,
                n,
                args.batch_size,
                circuit.num_gates,
                data.common.degree_bits(),
                build.as_secs_f64(),
                median(prove_times).as_secs_f64() * 1e3,
                size,
                median(verify_times).as_secs_f64() * 1e3,
            );
        }
    }
}
