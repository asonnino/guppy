use log::debug;
use log::info;
use plonky2::gates::noop::NoopGate;
use plonky2::hash::hash_types::HashOutTarget;
use plonky2::iop::target::BoolTarget;
use plonky2::iop::witness::PartialWitness;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::circuit_data::CircuitData;
use plonky2::plonk::circuit_data::CommonCircuitData;
use plonky2::plonk::circuit_data::VerifierCircuitTarget;
use plonky2::plonk::config::Hasher;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::plonk::proof::ProofWithPublicInputsTarget;
use plonky2::util::log2_ceil;
use plonky2::with_context;

use crate::merkle::add_merkle_proof_verification_to_circuit;
use crate::merkle::get_initial_root;
use crate::merkle::MerkleProofTargets;

// Plonky2 setup
pub const D: usize = 2;
pub type C = PoseidonGoldilocksConfig;
pub type F = <C as GenericConfig<D>>::F;
pub type H = <C as GenericConfig<D>>::Hasher;
pub type Digest = <H as Hasher<F>>::Hash;
pub type InnerHasher = <C as GenericConfig<D>>::InnerHasher;
pub type MyCircuitBuilder = CircuitBuilder<F, D>;
pub type MyPartialWitness = PartialWitness<F>;

pub struct AllTargets {
    pub condition: BoolTarget,
    pub inner_cyclic_proof_with_pis: ProofWithPublicInputsTarget<D>,
    pub verifier_data_target: VerifierCircuitTarget,
    pub prev_targets: Vec<MerkleProofTargets>,
    pub new_targets: Vec<MerkleProofTargets>,
}

// 2 m logn + 6300 (~6300 gates for the recursion)
fn estimate_degree_bits(max_levels: usize, num_checkpoint_updates: usize) -> usize {
    let num_gates = (2 * (max_levels + 1) * num_checkpoint_updates) + 6300;
    return log2_ceil(num_gates);
}

fn print_system_info(num_levels: usize, num_checkpoint_updates: usize) {
    info!(
        "Max Merkle tree levels: {} ({} elements)",
        num_levels,
        1 << (num_levels - 1)
    );
    info!(
        "Number of checkpoint updates (fixed): {}",
        num_checkpoint_updates
    );
}

// Returns the circuit along with the target wires needed to be set before proving
pub fn build_circuit(
    num_levels: usize,
    num_checkpoint_updates: usize,
    degree_bits: Option<usize>,
) -> (CircuitData<F, C, D>, AllTargets) {
    print_system_info(num_levels, num_checkpoint_updates);

    // Public inputs:
    // (i) zk service's state root,
    // (ii) checkpoint commitment,
    // (iii) counter / checkpoint number,
    // (iv) total number of leaves,
    // (v) verifier data
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // For the base case, in_root_t is the initial root. Otherwise, it is the previous root.
    let in_root_t = builder.add_virtual_hash();
    let mut out_root_t = in_root_t;

    let mut prev_targets = vec![];
    let mut new_targets = vec![];
    let mut checkpoint_commitment_inputs = vec![];

    // num_leaves_start will be connected to the number of leaves from the previous circuit.
    let in_num_leaves_t = builder.add_virtual_target();
    let mut out_num_leaves_t = in_num_leaves_t;

    let one = builder.one();
    let zero = builder.zero();

    with_context!(builder, "process checkpoint updates", {
        for _ in 0..num_checkpoint_updates {
            let t_cur: MerkleProofTargets;
            let t_new: MerkleProofTargets;
            // i) Check inclusion proof
            t_cur = add_merkle_proof_verification_to_circuit(&mut builder, num_levels);
            builder.connect_hashes(t_cur.root_t, out_root_t);
            prev_targets.push(t_cur.clone());

            // ii) Check inclusion proof after update
            t_new = add_merkle_proof_verification_to_circuit(&mut builder, num_levels);
            new_targets.push(t_new.clone());

            // iii) Connect the siblings
            assert_eq!(t_cur.proof_t.siblings.len(), t_new.proof_t.siblings.len());
            for i in 0..t_cur.proof_t.siblings.len() {
                builder.connect_hashes(t_cur.proof_t.siblings[i], t_new.proof_t.siblings[i]);
            }

            // (iv) Logic: If old leaf, check that stream IDs match. If new leaf, check that index is incremented.
            // if t_new.leaf_t.new_flag_t
            //  then assert (t_new.index_t == num_leaves) && (num_leaves += 1)
            // else assert (t_new.index_t == t_cur.index_t) && (t_new.leaf_t.stream_id_t == t_cur.leaf_t.stream_id_t)
            let b1 = builder.is_equal(t_new.index_t, out_num_leaves_t);
            let b2 = builder.is_equal(t_new.leaf_t.stream_id_t, t_cur.leaf_t.stream_id_t);
            let b3 = builder.is_equal(t_new.index_t, t_cur.index_t);
            let new_flag = t_new.leaf_t.new_flag_t;

            // if new_flag then b1 = true
            let b5 = builder.select(new_flag, b1.target, one);
            builder.assert_one(b5);

            let next_index = builder.add(out_num_leaves_t, one);
            out_num_leaves_t = builder.select(new_flag, next_index, out_num_leaves_t);

            // if not new_flag then b2 = true
            let b6 = builder.select(new_flag, one, b2.target);
            builder.assert_one(b6);

            // if not new_flag then b3 = true
            let b7 = builder.select(new_flag, one, b3.target);
            builder.assert_one(b7);

            // v) MerkleLeaf === StreamPoint, so we can use the same targets to compute the checkpoint commitment
            checkpoint_commitment_inputs.extend(t_new.leaf_t.get_all_targets());

            // vi) Update the current root
            out_root_t = t_new.root_t;
        }
    });

    // Register the final root as a public input
    builder.register_public_inputs(&out_root_t.elements);

    let cur_checkpoint_head = builder.add_virtual_hash_public_input();
    let checkpoint_commitment: HashOutTarget;
    with_context!(builder, "hash checkpoint commitment", {
        checkpoint_commitment = builder.hash_or_noop::<H>(checkpoint_commitment_inputs);
    });

    let counter = builder.add_virtual_public_input();
    builder.register_public_input(out_num_leaves_t);

    let expected_degree_bits =
        degree_bits.unwrap_or_else(|| estimate_degree_bits(num_levels, num_checkpoint_updates));
    debug!("Expected degree: 2^{}", expected_degree_bits);
    let verifier_data_target = builder.add_verifier_data_public_inputs();
    let common_data = common_data_for_recursion(expected_degree_bits, builder.num_public_inputs());

    // Condition is false for the base case, true for the recursive case.
    let condition = builder.add_virtual_bool_target_safe();

    // Unpack inner proof's public inputs.
    let inner_cyclic_proof_with_pis = builder.add_virtual_proof_with_pis(&common_data);
    let inner_cyclic_pis = &inner_cyclic_proof_with_pis.public_inputs;
    let inner_cyclic_latest_root = HashOutTarget::try_from(&inner_cyclic_pis[0..4]).unwrap();
    let inner_checkpoint_head = HashOutTarget::try_from(&inner_cyclic_pis[4..8]).unwrap();
    let inner_cyclic_counter = inner_cyclic_pis[8];
    let inner_num_leaves = inner_cyclic_pis[9];

    // Connect our initial root to that of our inner proof. (If there is no inner proof, the
    // initial hash will be unconstrained, which is intentional.)
    let inital_root_t = builder.constant_hash(get_initial_root(num_levels));

    // The input hash is the previous hash output if we have an inner proof, or the initial hash
    // if this is the base case.
    let actual_hash_in = HashOutTarget {
        elements: core::array::from_fn(|i| {
            builder.select(
                condition,
                inner_cyclic_latest_root.elements[i],
                inital_root_t.elements[i],
            )
        }),
    };
    builder.connect_hashes(in_root_t, actual_hash_in);

    let initial_head = builder.constant_hash(Digest::ZERO);
    let actual_head = HashOutTarget {
        elements: core::array::from_fn(|i| {
            builder.select(
                condition,
                inner_checkpoint_head.elements[i],
                initial_head.elements[i],
            )
        }),
    };
    // cur_head = H(inner_head || cur_commitment)
    let hash_chain_inputs = [actual_head.elements, checkpoint_commitment.elements].concat();
    let expected_checkpoint_head = builder.hash_or_noop::<H>(hash_chain_inputs);
    builder.connect_hashes(cur_checkpoint_head, expected_checkpoint_head);

    // Our chain length will be inner_counter + 1 if we have an inner proof, or 1 if not.
    let one = builder.one();
    let new_counter = builder.mul_add(condition.target, inner_cyclic_counter, one);
    builder.connect(counter, new_counter);

    let actual_in_num_leaves = builder.select(condition, inner_num_leaves, zero);
    builder.connect(in_num_leaves_t, actual_in_num_leaves);

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
        prev_targets,
        new_targets,
    };

    debug!("================================================");
    builder.print_gate_counts(0);
    debug!("================================================");

    (builder.build::<C>(), all_targets)
}

// Generates `CommonCircuitData` usable for recursion.
fn common_data_for_recursion(
    expected_degree_bits: usize,
    num_public_inputs: usize,
) -> CommonCircuitData<F, D> {
    let config = CircuitConfig::standard_recursion_config();
    let builder = CircuitBuilder::<F, D>::new(config);
    let data = builder.build::<C>();

    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    let proof = builder.add_virtual_proof_with_pis(&data.common);
    let verifier_data = builder.add_virtual_verifier_data(data.common.config.fri_config.cap_height);
    builder.verify_proof::<C>(&proof, &verifier_data, &data.common);
    let data = builder.build::<C>();

    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    let proof = builder.add_virtual_proof_with_pis(&data.common);
    let verifier_data = builder.add_virtual_verifier_data(data.common.config.fri_config.cap_height);
    builder.verify_proof::<C>(&proof, &verifier_data, &data.common);

    // Add noop gates until we reach the expected degree bits.
    //  We end the loop when num_gates reaches (1 << (expected_degree_bits - 1)) + 1.
    //  Padding takes care of the rest to ensure that the final gate count is 1 << expected_degree_bits.
    while builder.num_gates() < 1 << (expected_degree_bits - 1) {
        builder.add_gate(NoopGate, vec![]);
    }

    // Build the circuit
    let mut common_data = builder.build::<C>().common;
    assert!(common_data.degree_bits() == expected_degree_bits);
    common_data.num_public_inputs = num_public_inputs;
    common_data
}
