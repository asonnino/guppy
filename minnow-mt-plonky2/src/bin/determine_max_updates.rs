use std::env;
use std::process::{Command, Stdio};

fn debug(msg: &str) {
    eprintln!("{}", msg);
}

fn find_min_degree_bits(num_levels: u32, num_batches: u32, mut estimate_degree_bits: u32) -> u32 {
    let mut num_failures = 0;
    loop {
        let status = Command::new("cargo")
            .args(&[
                "run",
                "--release",
                "--",
                "-l",
                &num_levels.to_string(),
                "-n",
                &num_batches.to_string(),
                "-g",
                &estimate_degree_bits.to_string(),
                "-f",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("Failed to execute cargo run");

        if status.success() {
            break;
        }

        num_failures += 1;
        if num_failures == 3 {
            eprintln!(
                "Failed 3 times in a row. Exiting. Tried degree bits from {} to {}",
                estimate_degree_bits - 2,
                estimate_degree_bits
            );
            std::process::exit(0);
        }

        estimate_degree_bits += 1;
    }

    debug(&format!("Degree: {} {}", num_batches, estimate_degree_bits));

    estimate_degree_bits
}

fn find_change_point_sequentially(
    num_levels: u32,
    start_num_batches: u32,
    step: u32,
    estimate: u32,
) -> u32 {
    debug(&format!(
        "Finding change point starting from {} for 2**{} gates",
        start_num_batches, estimate
    ));

    let prev_bits = find_min_degree_bits(num_levels, start_num_batches, estimate);
    if prev_bits != estimate {
        eprintln!("Estimate is not equal to prev_bits");
        std::process::exit(1);
    }

    let mut num_batches = start_num_batches + step;

    loop {
        let bits = find_min_degree_bits(num_levels, num_batches, estimate);
        if bits != prev_bits {
            return num_batches - step;
        }
        num_batches += step;
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        eprintln!("Usage: {} <num_levels>", args[0]);
        std::process::exit(1);
    }

    let num_levels: u32 = args[1].parse().expect("Invalid num_levels");

    let mut cur_gates = 13;
    // let batch_size = 50;
    let mut cur_num_batches = 1;
    let step = 1;
    let end_gates = 18;

    while cur_gates != end_gates {
        let change_point =
            find_change_point_sequentially(num_levels, cur_num_batches, step, cur_gates);
        println!("Change point: {} {}", change_point, cur_gates);

        cur_num_batches = (change_point + step) * 2;
        cur_gates += 1;
    }
}
