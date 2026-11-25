//! The Minnow-H cyclic circuit. Public inputs: the validators' hash-chain head,
//! the commitment H(state list) to the tracked streams, and a checkpoint counter.
//! Private inputs: the previous proof, the checkpoint's updates (as batches),
//! and the previous state list.

use hashbrown::HashMap;
use log::debug;
use minnow_lib::utils::{Digest, Proof, C, D, F, H};
use plonky2::gates::noop::NoopGate;
use plonky2::plonk::circuit_data::CommonCircuitData;
use minnow_lib::{hash_commitment_t, Batch, StreamID, StreamPoint, StreamPointTarget};
use plonky2::hash::hash_types::HashOutTarget;
use plonky2::iop::target::BoolTarget;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData, VerifierCircuitTarget};
use plonky2::plonk::proof::ProofWithPublicInputsTarget;
use plonky2::recursion::dummy_circuit::cyclic_base_proof;
use plonky2::util::log2_ceil;
use plonky2::with_context;

use crate::MinnowHServiceState;

pub struct Targets {
    pub condition: BoolTarget,
    pub inner_cyclic_proof_with_pis: ProofWithPublicInputsTarget<D>,
    pub verifier_data_target: VerifierCircuitTarget,
    pub update_targets: Vec<Vec<StreamPointTarget>>,
    pub in_state_targets: Vec<StreamPointTarget>,
}

pub struct MinnowHCircuit {
    pub circuit_data: CircuitData<F, C, D>,
    pub targets: Targets,
    pub num_gates: usize,
    pub num_batches: usize,
    pub batch_size: usize,
}

impl MinnowHCircuit {
    /// Builds the circuit for checkpoints of `num_batches * batch_size` updates
    /// and the tracked set `tracked`. The recursion needs the circuit's own
    /// degree up front, so we build at an estimate and rebuild at the measured
    /// degree until the two agree.
    pub fn new(num_batches: usize, batch_size: usize, tracked: &[StreamID]) -> Self {
        let mut degree_bits = estimate_degree_bits(num_batches * batch_size, tracked.len());
        loop {
            let (circuit, matches) = build_circuit(num_batches, batch_size, tracked, degree_bits);
            let actual = circuit.circuit_data.common.degree_bits();
            if actual == degree_bits {
                assert!(matches, "circuit does not match its recursion data");
                return circuit;
            }
            debug!("degree estimate 2^{degree_bits}, built 2^{actual}; rebuilding");
            degree_bits = actual;
        }
    }

    pub fn base_proof(&self) -> Proof {
        cyclic_base_proof(
            &self.circuit_data.common,
            &self.circuit_data.verifier_only,
            HashMap::<usize, F>::new(),
        )
    }

    /// Proves one checkpoint: `state` is the state before `batches` are applied.
    pub fn prove(
        &self,
        batches: &[Batch],
        state: &MinnowHServiceState,
        prev_proof: &Proof,
        base_case: bool,
    ) -> Proof {
        let t = &self.targets;
        let mut pw = PartialWitness::new();
        pw.set_bool_target(t.condition, !base_case).unwrap();
        pw.set_proof_with_pis_target(&t.inner_cyclic_proof_with_pis, prev_proof)
            .unwrap();
        pw.set_verifier_data_target(&t.verifier_data_target, &self.circuit_data.verifier_only)
            .unwrap();

        assert_eq!(batches.len(), self.num_batches);
        for (batch, batch_t) in batches.iter().zip(&t.update_targets) {
            assert_eq!(batch.len(), self.batch_size);
            for (update, update_t) in batch.iter().zip(batch_t) {
                update_t.set_proof_targets(&mut pw, &update.encode());
            }
        }
        assert_eq!(state.len(), t.in_state_targets.len());
        for (point, point_t) in state.iter().zip(&t.in_state_targets) {
            point_t.set_proof_targets(&mut pw, &point.encode());
        }
        self.circuit_data.prove(pw).unwrap()
    }
}

/// About 25 arithmetic operations per (tracked stream, update) pair, about 20
/// operations per gate, plus about 6,300 gates for the recursive verifier.
fn estimate_degree_bits(num_updates: usize, num_tracked: usize) -> usize {
    log2_ceil(num_updates * num_tracked * 5 / 4 + num_updates / 2 + 6300)
}

fn initial_commitment(tracked: &[StreamID]) -> Digest {
    MinnowHServiceState::new(tracked).commit()
}

fn build_circuit(
    num_batches: usize,
    batch_size: usize,
    tracked: &[StreamID],
    degree_bits: usize,
) -> (MinnowHCircuit, bool) {
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // Public input 0..4: the validators' hash-chain head after this checkpoint.
    let head_pi = builder.add_virtual_hash_public_input();

    // Private: the checkpoint's updates and the previous state list.
    let update_targets: Vec<Vec<StreamPointTarget>> = (0..num_batches)
        .map(|_| (0..batch_size).map(|_| StreamPointTarget::new(&mut builder)).collect())
        .collect();
    let in_state_targets: Vec<StreamPointTarget> = tracked
        .iter()
        .map(|_| StreamPointTarget::new(&mut builder))
        .collect();

    // The previous list holds exactly the tracked identifiers, in order.
    for (point_t, id) in in_state_targets.iter().zip(tracked) {
        let encoded = StreamPoint::new(*id, [0; minnow_lib::STREAM_VAL_LEN]).encode();
        for (t, v) in point_t.stream_id_t.iter().zip(encoded.stream_id_f) {
            let c = builder.constant(v);
            builder.connect(*t, c);
        }
    }
    let in_flat: Vec<_> = in_state_targets.iter().flat_map(|p| p.get_all_targets()).collect();
    let in_commitment_t = builder.hash_or_noop::<H>(in_flat);

    // Apply the updates in order; a later update to the same stream wins.
    let mut out_state_targets = Vec::with_capacity(tracked.len());
    with_context!(builder, "apply checkpoint updates", {
        for point_t in &in_state_targets {
            let mut val_t = point_t.stream_val_t.clone();
            for update_t in update_targets.iter().flatten() {
                let mut same = builder._true();
                for (a, b) in point_t.stream_id_t.iter().zip(&update_t.stream_id_t) {
                    let eq = builder.is_equal(*a, *b);
                    same = builder.and(same, eq);
                }
                for (v, u) in val_t.iter_mut().zip(&update_t.stream_val_t) {
                    *v = builder.select(same, *u, *v);
                }
            }
            out_state_targets.push(StreamPointTarget::from_existing(
                point_t.stream_id_t.clone(),
                val_t,
                point_t.new_flag_t,
            ));
        }
    });

    // Public input 4..8: the commitment to the new state list.
    let out_flat: Vec<_> = out_state_targets.iter().flat_map(|p| p.get_all_targets()).collect();
    let out_commitment_t = builder.hash_or_noop::<H>(out_flat);
    builder.register_public_inputs(&out_commitment_t.elements);

    // Public input 8: the checkpoint counter.
    let counter = builder.add_virtual_public_input();

    let verifier_data_target = builder.add_verifier_data_public_inputs();
    // Large circuits verify their inner proof with an ExponentiationGate, which the
    // generic recursion template lacks; use it once here and in the template so
    // that both always have the same gate set.
    add_exponentiation_gate(&mut builder);
    let common_data = recursion_template(degree_bits, builder.num_public_inputs());

    let condition = builder.add_virtual_bool_target_safe(); // false in the base case
    let inner = builder.add_virtual_proof_with_pis(&common_data);
    let inner_head = HashOutTarget::try_from(&inner.public_inputs[0..4]).unwrap();
    let inner_commitment = HashOutTarget::try_from(&inner.public_inputs[4..8]).unwrap();
    let inner_counter = inner.public_inputs[8];

    // Previous state: the inner proof's, or the initial list in the base case.
    let init_commitment = builder.constant_hash(initial_commitment(tracked));
    let prev_commitment = select_hash(&mut builder, condition, inner_commitment, init_commitment);
    builder.connect_hashes(in_commitment_t, prev_commitment);

    // Previous head: the inner proof's, or the initial head in the base case;
    // then extend the chain with this checkpoint's batches, as validators do.
    let init_head = builder.constant_hash(Digest::ZERO);
    let prev_head = select_hash(&mut builder, condition, inner_head, init_head);
    let head_t;
    with_context!(builder, "validator hash chain", {
        head_t = hash_commitment_t(&update_targets, &prev_head, &mut builder);
    });
    builder.connect_hashes(head_pi, head_t);

    let one = builder.one();
    let new_counter = builder.mul_add(condition.target, inner_counter, one);
    builder.connect(counter, new_counter);

    with_context!(builder, "verify inner proof", {
        builder
            .conditionally_verify_cyclic_proof_or_dummy::<C>(condition, &inner, &common_data)
            .unwrap();
    });

    let num_gates = builder.num_gates();
    // `build` panics when the circuit's shape differs from `common_data`; the
    // caller compares degrees and rebuilds instead.
    let (circuit_data, matches) = builder.try_build_with_options::<C>(true);
    let circuit = MinnowHCircuit {
        circuit_data,
        targets: Targets {
            condition,
            inner_cyclic_proof_with_pis: inner,
            verifier_data_target,
            update_targets,
            in_state_targets,
        },
        num_gates,
        num_batches,
        batch_size,
    };
    (circuit, matches)
}

fn select_hash(
    builder: &mut CircuitBuilder<F, D>,
    b: BoolTarget,
    x: HashOutTarget,
    y: HashOutTarget,
) -> HashOutTarget {
    HashOutTarget {
        elements: core::array::from_fn(|i| builder.select(b, x.elements[i], y.elements[i])),
    }
}

fn add_exponentiation_gate(builder: &mut CircuitBuilder<F, D>) {
    let one = builder.one();
    let bit = builder._false();
    builder.exp_from_bits(one, [bit]);
}

/// `minnow_lib::utils::common_data_for_recursion`, plus an ExponentiationGate.
fn recursion_template(degree_bits: usize, num_public_inputs: usize) -> CommonCircuitData<F, D> {
    let config = CircuitConfig::standard_recursion_config();
    let data = CircuitBuilder::<F, D>::new(config.clone()).build::<C>();

    let mut builder = CircuitBuilder::<F, D>::new(config.clone());
    let proof = builder.add_virtual_proof_with_pis(&data.common);
    let vd = builder.add_virtual_verifier_data(data.common.config.fri_config.cap_height);
    builder.verify_proof::<C>(&proof, &vd, &data.common);
    let data = builder.build::<C>();

    let mut builder = CircuitBuilder::<F, D>::new(config);
    let proof = builder.add_virtual_proof_with_pis(&data.common);
    let vd = builder.add_virtual_verifier_data(data.common.config.fri_config.cap_height);
    builder.verify_proof::<C>(&proof, &vd, &data.common);
    add_exponentiation_gate(&mut builder);
    while builder.num_gates() < 1 << (degree_bits - 1) {
        builder.add_gate(NoopGate, vec![]);
    }
    let mut common = builder.build::<C>().common;
    assert_eq!(common.degree_bits(), degree_bits);
    common.num_public_inputs = num_public_inputs;
    common
}
