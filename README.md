# Minnow

Light clients with completeness on chains whose validators commit only to the
updates of each checkpoint. Validators extend a batched hash chain over each
checkpoint's stream updates; an untrusted ZK service maintains a Merkle tree over the
full state and proves every update with recursive Plonky2 proofs, so a client can
check the state of any stream at any checkpoint from one proof, one Merkle path, and
one signed checkpoint header.

## Crates

| Crate | Contents |
|---|---|
| `minnow-lib` | Shared types and the validator-side commitment (batched hash chain). |
| `minnow-mt-plonky2` | Merkle-tree circuits: Minnow-A (one recursive circuit per bundle) and the base, aggregation, and cyclic circuits of Minnow-B; circuit-size tools and benchmarks. |
| `minnow-h-plonky2` | Minnow-H: the ZK service tracks a fixed set of streams and commits to them with one hash over the list. |
| `minnow-core` | The distributed Minnow-B prover (primary, workers, clients). |
| `orchestrator` | Deploys and benchmarks `minnow-core` on cloud machines; see [`orchestrator/readme.md`](orchestrator/readme.md). |
| `sp1` | An exploratory SP1 (zkVM) port, not used in the measurements below. |

## Reproducing the measurements

Requires a recent Rust toolchain (see `rust-toolchain`). All commands run from the
repository root.

```sh
# Validator-side commitment time by batch size and number of updates
cargo bench -p minnow-lib --bench hash_commitment

# Plonky2 proving time by circuit degree
cargo bench -p minnow-mt-plonky2 --bench proving

# Client verification of Minnow-A and Minnow-B proofs (compressed and not)
cargo bench -p minnow-mt-plonky2 --bench verifying

# Circuit sizes (gates and degree)
cargo run --release -p minnow-mt-plonky2 --bin circuit_sizes -- base             # base circuit by updates
cargo run --release -p minnow-mt-plonky2 --bin circuit_sizes -- base_batch_sizes # base circuit by batch size
cargo run --release -p minnow-mt-plonky2 --bin circuit_sizes -- one_step         # Minnow-A circuit
cargo run --release -p minnow-mt-plonky2 --bin circuit_sizes -- compressed       # aggregation circuit

# Maximum updates per Minnow-A proof at degrees 14-17, for 2^30 streams (also 10, 20)
cargo run --release -p minnow-mt-plonky2 --bin determine_max_updates -- 30

# Minnow-H: proving time, proof size, and verification time by tracked streams and updates
cargo run --release -p minnow-h-plonky2 -- --tracked 1,4,16,64 --updates 100,1000,2100

# Tests
cargo test --release
```

End-to-end Minnow-B runs (latency and throughput on several machines) use the
orchestrator; follow [`orchestrator/readme.md`](orchestrator/readme.md).
