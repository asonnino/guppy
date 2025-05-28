use minnow_lib::utils::CircuitInfo;
use minnow_mt_plonky2::one_step_circuit::MinnowMTOneStepCircuit;
use minnow_mt_plonky2::three_step_circuit::CompressedCircuit;
use minnow_mt_plonky2::two_step_circuit::BaseCircuit;
use minnow_mt_plonky2::DEFAULT_BATCH_SIZE;
use std::env;

fn measure_base_circuit_for_different_batch_sizes() {
    println!("Base Circuit Parameters:");
    println!("============================");
    let log_state_size = 20;
    let batch_sizes = [10, 100, 1000];
    let num_checkpoint_updates = 1000;
    println!("Batch Size\tGates\tDegree Bits");
    println!("----------------------------------------------------------");
    for batch_size in batch_sizes {
        let num_batches = num_checkpoint_updates / batch_size;
        assert!(num_batches * batch_size == num_checkpoint_updates);
        let circuit = BaseCircuit::new(log_state_size, num_batches, batch_size);
        let cur_info = circuit.circuit_info;
        println!(
            "{}\t{}\t{}",
            batch_size, cur_info.num_gates, cur_info.degree_bits
        );
    }
}

fn measure_one_step_circuit() {
    println!("One Step Circuit Parameters:");
    println!("============================");
    let log_state_sizes = [10, 20];
    let start_num_checkpoint_updates = 50;
    let end_num_checkpoint_updates = 500;
    let step = 50;

    let mut prev_info = CircuitInfo {
        num_gates: 0,
        degree_bits: 0,
    };

    println!("Log State Size\tNum Checkpoint Updates\tGates\tDegree Bits");
    println!("----------------------------------------------------------");

    for log_state_size in log_state_sizes {
        for num_checkpoint_updates in
            (start_num_checkpoint_updates..=end_num_checkpoint_updates).step_by(step)
        {
            let num_batches = num_checkpoint_updates / DEFAULT_BATCH_SIZE;
            assert!(num_batches * DEFAULT_BATCH_SIZE == num_checkpoint_updates);
            let circuit =
                MinnowMTOneStepCircuit::new(log_state_size, num_batches, DEFAULT_BATCH_SIZE, None);
            let cur_info = circuit.circuit_info;
            if cur_info.degree_bits != prev_info.degree_bits {
                println!(
                    "{}\t{}\t{}\t{}",
                    log_state_size,
                    num_checkpoint_updates,
                    cur_info.num_gates,
                    cur_info.degree_bits
                );
            }
            prev_info = cur_info;
        }
    }
}

fn measure_base_circuit() {
    println!("Base Circuit Parameters:");
    println!("=======================");
    let log_state_size = 30;
    let start_num_checkpoint_updates = 50;
    let step = 50;
    let end_num_checkpoint_updates = 2000;
    let mut prev_info = CircuitInfo {
        num_gates: 0,
        degree_bits: 0,
    };

    println!("Updates\tGates\tDegree Bits");
    println!("------------------------");

    for num_checkpoint_updates in
        (start_num_checkpoint_updates..=end_num_checkpoint_updates).step_by(step)
    {
        let num_batches = num_checkpoint_updates / DEFAULT_BATCH_SIZE;
        assert!(num_batches * DEFAULT_BATCH_SIZE == num_checkpoint_updates);
        let circuit = BaseCircuit::new(log_state_size, num_batches, DEFAULT_BATCH_SIZE);
        let cur_info = circuit.circuit_info;
        if cur_info.degree_bits != prev_info.degree_bits {
            println!(
                "{}\t{}\t{}",
                num_checkpoint_updates - step,
                prev_info.num_gates,
                prev_info.degree_bits
            );
        }
        prev_info = cur_info;
    }
}

fn measure_compressed_circuit() {
    println!("Compressed Circuit Parameters:");
    println!("============================");
    let log_state_size = 20;
    let num_checkpoint_updates = 500;
    let num_batches = num_checkpoint_updates / DEFAULT_BATCH_SIZE;
    assert!(num_batches * DEFAULT_BATCH_SIZE == num_checkpoint_updates);
    let base_circuit = BaseCircuit::new(log_state_size, num_batches, DEFAULT_BATCH_SIZE);
    println!("Base circuit info: {:?}", base_circuit.circuit_info);

    println!("\nBranching Factor\tGates\tDegree Bits");
    println!("--------------------------------");
    for branching_factor in [2, 3, 4, 5, 6, 7, 8, 9, 10] {
        let compressed_circuit =
            CompressedCircuit::new(&base_circuit.circuit_data, branching_factor);
        println!(
            "{}\t{}\t{}",
            branching_factor,
            compressed_circuit.circuit_info.num_gates,
            compressed_circuit.circuit_info.degree_bits
        );
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() > 1 && args[1] == "compressed" {
        measure_compressed_circuit();
    } else if args.len() > 1 && args[1] == "one_step" {
        measure_one_step_circuit();
    } else if args.len() > 1 && args[1] == "base_batch_sizes" {
        measure_base_circuit_for_different_batch_sizes();
    } else if args.len() > 1 && args[1] == "base" {
        measure_base_circuit();
    } else {
        println!("Usage: cargo run --bin circuit_sizes [compressed|one_step|base]");
    }
}
