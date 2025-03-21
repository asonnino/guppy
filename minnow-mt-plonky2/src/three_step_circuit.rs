use log::info;
use plonky2::hash::hash_types::HashOutTarget;
use plonky2::iop::witness::PartialWitness;
use plonky2::iop::witness::WitnessWrite;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::circuit_data::CircuitData;
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::plonk::proof::ProofWithPublicInputsTarget;
use plonky2::with_context;

use crate::merkle::get_initial_root;
use crate::two_step_circuit::{BaseCircuit, CyclicSequentialCircuit};

use minnow_lib::utils::CircuitInfo;
use minnow_lib::utils::{C, D, F};

pub struct ThreeStepMinnowMTCircuits {
    pub base_circuit: BaseCircuit,
    /// should be a power of 2
    pub num_base_circuits_to_compress: usize,
    /// length equals to num_base_circuits_to_compress.log2()
    pub compressed_circuits: Vec<CompressedCircuit>,
    pub sequential_circuit: CyclicSequentialCircuit,
}

impl ThreeStepMinnowMTCircuits {
    pub fn new(log_state_size: usize, num_updates_per_time_slot: usize, batch_size: usize) -> Self {
        assert!(num_updates_per_time_slot % batch_size == 0);
        let base_circuit = BaseCircuit::new(log_state_size, batch_size);

        let num_base_circuits_to_compress = num_updates_per_time_slot / batch_size;

        // num_proofs_to_compress_per_level
        let branching_factor = 2;
        assert!(num_base_circuits_to_compress.is_power_of_two());

        let log_num_base_circuits_to_compress = num_base_circuits_to_compress.ilog2();
        let mut compressed_circuits: Vec<CompressedCircuit> = vec![];
        for _ in 0..log_num_base_circuits_to_compress {
            if let Some(last_circuit_data) = compressed_circuits.last() {
                let compressed_circuit =
                    CompressedCircuit::new(&last_circuit_data.circuit_data, branching_factor);
                compressed_circuits.push(compressed_circuit);
            } else {
                let compressed_circuit =
                    CompressedCircuit::new(&base_circuit.circuit_data, branching_factor);
                compressed_circuits.push(compressed_circuit);
            }
        }

        let root_circuit = compressed_circuits.last().unwrap();

        let initial_root = get_initial_root(log_state_size + 1);
        let sequential_circuit =
            CyclicSequentialCircuit::new(&initial_root, &root_circuit.circuit_data);
        Self {
            base_circuit,
            num_base_circuits_to_compress,
            compressed_circuits,
            sequential_circuit,
        }
    }
}

pub struct CompressedCircuit {
    pub circuit_info: CircuitInfo,
    pub circuit_data: CircuitData<F, C, D>,
    pub targets: Targets,
}

pub struct Targets {
    pub in_proofs: Vec<ProofWithPublicInputsTarget<D>>,
}

impl CompressedCircuit {
    pub fn new(in_circuit_data: &CircuitData<F, C, D>, num_proofs_to_compress: usize) -> Self {
        info!(
            "Building compressed circuit for {:?}",
            in_circuit_data.verifier_only.circuit_digest
        );
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let mut in_proofs = vec![];
        let mut cur_num_leaves = builder.add_virtual_target();
        let mut cur_checkpoint_head = builder.add_virtual_hash();
        let mut cur_mt_root = builder.add_virtual_hash();
        for i in 0..num_proofs_to_compress {
            let in_common_data = &in_circuit_data.common;
            let in_proof_with_pis = builder.add_virtual_proof_with_pis(in_common_data);
            let in_verifier_data_target =
                builder.constant_verifier_data(&in_circuit_data.verifier_only);
            with_context!(builder, "verify in proof", {
                builder.verify_proof::<C>(
                    &in_proof_with_pis,
                    &in_verifier_data_target,
                    &in_common_data,
                );
            });
            let in_num_leaves = in_proof_with_pis.public_inputs[0];
            let out_num_leaves = in_proof_with_pis.public_inputs[1];
            let in_mt_root =
                HashOutTarget::try_from(&in_proof_with_pis.public_inputs[2..6]).unwrap();
            let out_mt_root =
                HashOutTarget::try_from(&in_proof_with_pis.public_inputs[6..10]).unwrap();
            let in_checkpoint_head =
                HashOutTarget::try_from(&in_proof_with_pis.public_inputs[10..14]).unwrap();
            let out_checkpoint_head =
                HashOutTarget::try_from(&in_proof_with_pis.public_inputs[14..18]).unwrap();
            if i != 0 {
                builder.connect(cur_num_leaves, in_num_leaves);
                builder.connect_hashes(cur_checkpoint_head, in_checkpoint_head);
                builder.connect_hashes(cur_mt_root, in_mt_root);
            }
            cur_num_leaves = out_num_leaves;
            cur_checkpoint_head = out_checkpoint_head;
            cur_mt_root = out_mt_root;
            in_proofs.push(in_proof_with_pis);
        }

        // Make the first proof's inputs and last proof's outputs public.
        // We retain the same shape for the pub inputs as the BaseCircuit.
        let first_proof = in_proofs.first().unwrap();
        let last_proof = in_proofs.last().unwrap();

        builder.register_public_input(first_proof.public_inputs[0]);
        builder.register_public_input(last_proof.public_inputs[1]);

        builder.register_public_inputs(&first_proof.public_inputs[2..6]);
        builder.register_public_inputs(&last_proof.public_inputs[6..10]);

        builder.register_public_inputs(&first_proof.public_inputs[10..14]);
        builder.register_public_inputs(&last_proof.public_inputs[14..18]);

        let num_gates = builder.num_gates();
        info!("Compressed circuit built: {} gates", num_gates);
        let circuit_data = builder.build::<C>();

        CompressedCircuit {
            circuit_info: CircuitInfo {
                num_gates,
                degree_bits: circuit_data.common.degree_bits(),
            },
            circuit_data,
            targets: Targets { in_proofs },
        }
    }

    pub fn set_inputs(&self, in_proofs: &[&ProofWithPublicInputs<F, C, D>]) -> PartialWitness<F> {
        let mut pw = PartialWitness::new();
        for i in 0..self.targets.in_proofs.len() {
            pw.set_proof_with_pis_target(&self.targets.in_proofs[i], &in_proofs[i])
                .unwrap();
        }
        pw
    }
}

mod tests {

    #[test]
    fn test_compressed_circuit() {
        // init_logging(log::LevelFilter::Debug);
        let log_state_size = 10;
        let num_checkpoint_updates = 300;
        let mut zk_service_state = MinnowMTServiceState::new(&[], log_state_size);
        let circuit = BaseCircuit::new(log_state_size, num_checkpoint_updates);

        // Generate two base proofs
        let all_checkpoint_updates = generate_sample_checkpoint_updates(2, num_checkpoint_updates);
        let mut head = Digest::ZERO;
        let pw = circuit.apply_checkpoint_updates_and_set_inputs(
            &all_checkpoint_updates[0],
            &mut zk_service_state,
            &head,
        );
        let base_proof_0 = circuit.circuit_data.prove(pw).unwrap();
        head = commit_single_update(&all_checkpoint_updates[0], &head);
        let pw = circuit.apply_checkpoint_updates_and_set_inputs(
            &all_checkpoint_updates[1],
            &mut zk_service_state,
            &head,
        );
        let base_proof_1 = circuit.circuit_data.prove(pw).unwrap();

        let compressed_circuit = CompressedCircuit::new(&circuit.circuit_data, 2);
        let pw = compressed_circuit.set_inputs(&[&base_proof_0, &base_proof_1]);
        let start = Instant::now();
        let combined_proof = compressed_circuit.circuit_data.prove(pw).unwrap();
        let end = Instant::now();
        info!("Proof generation time: {:?}", end.duration_since(start));
        compressed_circuit
            .circuit_data
            .verify(combined_proof.clone())
            .unwrap();
        assert_eq!(
            combined_proof.public_inputs[0],
            base_proof_0.public_inputs[0]
        );
        assert_eq!(
            combined_proof.public_inputs[1],
            base_proof_1.public_inputs[1]
        );
        assert_eq!(
            combined_proof.public_inputs[2..6],
            base_proof_0.public_inputs[2..6]
        );
        assert_eq!(
            combined_proof.public_inputs[6..10],
            base_proof_1.public_inputs[6..10]
        );
        assert_eq!(
            combined_proof.public_inputs[10..14],
            base_proof_0.public_inputs[10..14]
        );
        assert_eq!(
            combined_proof.public_inputs[14..18],
            base_proof_1.public_inputs[14..18]
        );
    }

    #[test]
    fn test_compressed_circuit_basic() {
        let log_state_size = 30;
        let num_checkpoint_updates = 500;
        let base_circuit = BaseCircuit::new(log_state_size, 1900);
        let compressed_circuit = CompressedCircuit::new(&base_circuit.circuit_data, 3);
        println!(
            "Compressed circuit info: {:?}",
            compressed_circuit.circuit_info
        );
    }

    #[test]
    fn bench_compressed_circuit_branching_factor() {
        let log_state_size = 20;
        let num_checkpoint_updates = 500;
        let base_circuit = BaseCircuit::new(log_state_size, num_checkpoint_updates);
        println!("Base circuit info: {:?}", base_circuit.circuit_info);
        for branching_factor in [2, 3, 4, 5, 6, 7, 8, 9, 10] {
            let compressed_circuit =
                CompressedCircuit::new(&base_circuit.circuit_data, branching_factor);
            println!(
                "Branching factor: {}, Compressed circuit info: {:?}",
                branching_factor, compressed_circuit.circuit_info
            );
        }
    }

    #[test]
    fn test_three_step_circuit() {
        let log_state_size = 30;
        let num_checkpoint_updates = 500;
        let three_step_circuit = ThreeStepMinnowMTCircuits::new(log_state_size, 50000, 1900);
        println!(
            "Three step circuit info: {:?}",
            three_step_circuit.base_circuit.circuit_info
        );
        println!(
            "Three step circuit info: {:?}",
            three_step_circuit.compressed_circuits[0].circuit_info
        );
        println!(
            "Three step circuit info: {:?}",
            three_step_circuit.sequential_circuit.circuit_info
        );
    }
}
