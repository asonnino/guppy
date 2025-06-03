use hashbrown::HashMap;
use plonky2::{
    field::goldilocks_field::GoldilocksField,
    iop::{target::Target, witness::PartialWitness},
    plonk::{config::PoseidonGoldilocksConfig, proof::ProofWithPublicInputs},
};
use serde::{ser::SerializeStruct, Deserialize, Deserializer, Serialize};
use tokio::sync::mpsc;

use crate::two_step_circuit::BaseCircuit;

/// Simulates a multi-machine setup where the primary generates partial witnesses
/// and sends them to the proxy provers, which then compute base proofs.
pub struct PartialWitnessMessage {
    pub index: u64,
    pub witness: PartialWitness<GoldilocksField>,
}

impl Serialize for PartialWitnessMessage {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("PartialWitnessMessage", 2)?;
        state.serialize_field("index", &self.index)?;
        let witness_map: &HashMap<Target, GoldilocksField> = &self.witness.target_values;
        state.serialize_field("witness", witness_map)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for PartialWitnessMessage {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct PartialWitnessMessageHelper {
            index: u64,
            witness: HashMap<Target, GoldilocksField>,
        }

        let helper = PartialWitnessMessageHelper::deserialize(deserializer)?;
        Ok(PartialWitnessMessage {
            index: helper.index,
            witness: PartialWitness {
                target_values: helper.witness,
            },
        })
    }
}

/// Simulates a multi-machine setup where the proxy prover sends back the base proof
/// to the primary, which then computes the cyclic proof.
#[derive(Serialize, Deserialize)]
pub struct BaseProofMessage {
    pub index: u64,
    pub proof: ProofWithPublicInputs<GoldilocksField, PoseidonGoldilocksConfig, 2>,
}

/// Spawns a task that simulates a proxy prover, which receives partial witnesses
/// and computes base proofs.
pub async fn spawn_proxy_prover(
    mut rx: mpsc::Receiver<Vec<u8>>,
    tx: mpsc::Sender<Vec<u8>>,
    base_circuit: &BaseCircuit,
) {
    while let Some(serialized) = rx.recv().await {
        let message = bincode::deserialize(&serialized).unwrap();
        let PartialWitnessMessage { index, witness } = message;
        let proof = base_circuit.circuit_data.prove(witness).unwrap();
        assert!(base_circuit.circuit_data.verify(proof.clone()).is_ok());
        let reply = BaseProofMessage { index, proof };
        let reply_serialized = bincode::serialize(&reply).unwrap();
        tx.send(reply_serialized).await.unwrap();
    }
}
