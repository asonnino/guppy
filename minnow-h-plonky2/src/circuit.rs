use log::debug;
use minnow_mt_plonky2::utils::{common_data_for_recursion, Digest, C, D, F, H};
use minnow_mt_plonky2::merkle::LeafTarget;
use minnow_mt_plonky2::{StreamID, STREAM_VAL_LEN_F};
use plonky2::hash::hash_types::HashOutTarget;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData, VerifierCircuitTarget};
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::plonk::proof::ProofWithPublicInputsTarget;
use plonky2::util::log2_ceil;
use plonky2::with_context;

use crate::MinnowHServiceState;

// We do not need the new flag in the StreamPointTarget for the sparse node use cases.
// Reusing what's existing for simplicity. We just set it to false in the service's state.
pub type StreamPointTarget = LeafTarget;

pub struct StreamPointVecTarget {
    pub targets: Vec<StreamPointTarget>,
}

impl StreamPointVecTarget {
    pub fn new(builder: &mut CircuitBuilder<F, D>, num_streams: usize) -> Self {
        let mut targets = vec![];
        for _ in 0..num_streams {
            targets.push(StreamPointTarget::new(builder));
        }
        Self { targets }
    }

    pub fn get_all_targets(&self) -> Vec<Target> {
        self.targets
            .iter()
            .map(|t| t.get_all_targets())
            .flatten()
            .collect()
    }

    pub fn len(&self) -> usize {
        self.targets.len()
    }

    pub fn iter(&self) -> std::slice::Iter<StreamPointTarget> {
        self.targets.iter()
    }
}

pub struct AllTargets {
    pub condition: BoolTarget,
    pub inner_cyclic_proof_with_pis: ProofWithPublicInputsTarget<D>,
    pub verifier_data_target: VerifierCircuitTarget,
    pub checkpoint_update_targets: StreamPointVecTarget,
    pub in_state_targets: StreamPointVecTarget,
}

fn get_initial_commitment(tracking_streams: &[StreamID]) -> Digest {
    let state = MinnowHServiceState::new(tracking_streams);
    state.commit()
}

fn estimate_degree_bits(num_checkpoint_updates: usize, num_tracking_streams: usize) -> usize {
    let num_gates = (num_checkpoint_updates * num_tracking_streams * STREAM_VAL_LEN_F) + 6300;
    return log2_ceil(num_gates);
}

pub fn build_circuit(
    num_checkpoint_updates: usize,
    tracking_streams: &[StreamID],
    degree_bits: Option<usize>,
) -> (CircuitData<F, C, D>, AllTargets) {
    let num_tracking_streams = tracking_streams.len();
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // Public inputs:
    // (i) zk service's state commitment,
    // (ii) checkpoint commitment,
    // (iii) counter

    // Private inputs:
    // (i) checkpoint updates vector
    // (ii) current state vector
    // (iii) condition

    let checkpoint_update_t = StreamPointVecTarget::new(&mut builder, num_checkpoint_updates);
    let cur_checkpoint_head_pi = builder.add_virtual_hash_public_input();
    let checkpoint_commitment: HashOutTarget;
    with_context!(builder, "hash checkpoint commitment", {
        checkpoint_commitment = builder.hash_or_noop::<H>(checkpoint_update_t.get_all_targets());
    });

    let in_state_t = StreamPointVecTarget::new(&mut builder, num_tracking_streams);
    let mut in_commitment_t = builder.add_virtual_hash();
    with_context!(builder, "hash past state commitment", {
        in_commitment_t = builder.hash_or_noop::<H>(in_state_t.get_all_targets());
    });

    let mut out_state_t = StreamPointVecTarget::new(&mut builder, 0);
    with_context!(builder, "process checkpoint updates", {
        for x in &in_state_t.targets {
            let stream_id_t = x.stream_id_t;
            let mut cur_val_t = x.stream_val_t.clone();

            for y in &checkpoint_update_t.targets {
                let update_id_t = y.stream_id_t;
                let new_val_t = &y.stream_val_t;

                let b = builder.is_equal(stream_id_t, update_id_t);
                for i in 0..STREAM_VAL_LEN_F {
                    cur_val_t[i] = builder.select(b, new_val_t[i], cur_val_t[i]);
                }
            }
            out_state_t.targets.push(StreamPointTarget::from_existing(
                stream_id_t,
                cur_val_t.to_vec(),
                builder._false(),
            ));
        }
    });

    // Register the final service state's commitment as a public input
    let out_commitment_t = builder.hash_or_noop::<H>(out_state_t.get_all_targets());
    builder.register_public_inputs(&out_commitment_t.elements);

    let counter = builder.add_virtual_public_input();

    let expected_degree_bits = degree_bits
        .unwrap_or_else(|| estimate_degree_bits(num_checkpoint_updates, num_tracking_streams));
    debug!("Expected degree: 2^{}", expected_degree_bits);
    let verifier_data_target = builder.add_verifier_data_public_inputs();
    let common_data = common_data_for_recursion(expected_degree_bits, builder.num_public_inputs());

    // Unpack inner proof's public inputs.
    let inner_cyclic_proof_with_pis = builder.add_virtual_proof_with_pis(&common_data);
    let inner_cyclic_pis = &inner_cyclic_proof_with_pis.public_inputs;
    let inner_checkpoint_head_t = HashOutTarget::try_from(&inner_cyclic_pis[0..4]).unwrap();
    let inner_commitment_t = HashOutTarget::try_from(&inner_cyclic_pis[4..8]).unwrap();
    let inner_cyclic_counter = inner_cyclic_pis[8];

    // Condition is false for the base case, true for the recursive case.
    let condition = builder.add_virtual_bool_target_safe();

    // Connect our initial root to that of our inner proof. (If there is no inner proof, the
    // initial hash will be unconstrained, which is intentional.)
    let inital_commitment_t = builder.constant_hash(get_initial_commitment(&tracking_streams));

    // The input hash is the previous hash output if we have an inner proof, or the initial hash
    // if this is the base case.
    let actual_commitment_in = HashOutTarget {
        elements: core::array::from_fn(|i| {
            builder.select(
                condition,
                inner_commitment_t.elements[i],
                inital_commitment_t.elements[i],
            )
        }),
    };
    builder.connect_hashes(in_commitment_t, actual_commitment_in);

    let initial_head = builder.constant_hash(Digest::ZERO);
    let actual_head = HashOutTarget {
        elements: core::array::from_fn(|i| {
            builder.select(
                condition,
                inner_checkpoint_head_t.elements[i],
                initial_head.elements[i],
            )
        }),
    };
    // cur_head = H(inner_head || cur_commitment)
    let hash_chain_inputs = [actual_head.elements, checkpoint_commitment.elements].concat();
    let expected_checkpoint_head = builder.hash_or_noop::<H>(hash_chain_inputs);
    builder.connect_hashes(cur_checkpoint_head_pi, expected_checkpoint_head);

    // Our chain length will be inner_counter + 1 if we have an inner proof, or 1 if not.
    let one = builder.one();
    let new_counter = builder.mul_add(condition.target, inner_cyclic_counter, one);
    builder.connect(counter, new_counter);

    with_context!(builder, "verify inner proof", {
        builder
            .conditionally_verify_cyclic_proof_or_dummy::<C>(
                condition,
                &inner_cyclic_proof_with_pis,
                &common_data,
            )
            .unwrap();
    });
    let all_targets = AllTargets {
        condition,
        inner_cyclic_proof_with_pis,
        verifier_data_target,
        checkpoint_update_targets: checkpoint_update_t,
        in_state_targets: in_state_t,
    };

    debug!("================================================");
    builder.print_gate_counts(0);
    debug!("================================================");

    (builder.build::<C>(), all_targets)
}
