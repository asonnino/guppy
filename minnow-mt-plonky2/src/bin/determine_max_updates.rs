use std::env;
use std::process::{Command, Stdio};

fn debug(msg: &str) {
    eprintln!("{}", msg);
}

fn find_min_degree_bits(
    num_levels: u32,
    num_checkpoint_updates: u32,
    mut estimate_degree_bits: u32,
) -> u32 {
    let mut num_failures = 0;
    loop {
        let status = Command::new("cargo")
            .args(&[
                "run",
                "--release",
                "--",
                "-l",
                &num_levels.to_string(),
                "-c",
                &num_checkpoint_updates.to_string(),
                "-g",
                &estimate_degree_bits.to_string(),
                "-b",
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

    debug(&format!(
        "Degree: {} {}",
        num_checkpoint_updates, estimate_degree_bits
    ));

    estimate_degree_bits
}

fn find_change_point_sequentially(
    num_levels: u32,
    start_updates: u32,
    step: u32,
    estimate: u32,
) -> u32 {
    debug(&format!(
        "Finding change point starting from {} for 2**{} gates",
        start_updates, estimate
    ));

    let prev_bits = find_min_degree_bits(num_levels, start_updates, estimate);
    if prev_bits != estimate {
        eprintln!("Estimate is not equal to prev_bits");
        std::process::exit(1);
    }

    let mut num_checkpoint_updates = start_updates + step;

    loop {
        let bits = find_min_degree_bits(num_levels, num_checkpoint_updates, estimate);
        if bits != prev_bits {
            return num_checkpoint_updates - step;
        }
        num_checkpoint_updates += step;
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
    let mut cur_updates = 50;
    let step = 50;
    let end_gates = 18;

    while cur_gates != end_gates {
        let change_point = find_change_point_sequentially(num_levels, cur_updates, step, cur_gates);
        println!("Change point: {} {}", change_point, cur_gates);

        cur_updates = (change_point + step) * 2;
        cur_gates += 1;
    }
}
