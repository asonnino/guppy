use minnow_lib::{check_sorted, BatchCheckpointUpdates, CheckpointUpdates, StreamPoint};
use sp1_sdk::{
    ExecutionReport,
    ProverClient,
    SP1ProofWithPublicValues,
    SP1ProvingKey,
    SP1PublicValues,
    SP1Stdin,
    SP1VerifyingKey,
};

pub struct ProverEnv<'a> {
    pub client: ProverClient,
    pub proving_key: SP1ProvingKey,
    pub verifying_key: SP1VerifyingKey,
    pub stdin: SP1Stdin,
    pub elf: &'a [u8],
}

impl<'a> ProverEnv<'a> {
    pub fn prove(&self) -> anyhow::Result<SP1ProofWithPublicValues> {
        // Generate the proof
        self.client
            .prove(&self.proving_key, self.stdin.clone())
            .run()
    }

    pub fn execute(&self) -> anyhow::Result<(SP1PublicValues, ExecutionReport)> {
        // Execute the program
        self.client.execute(self.elf, self.stdin.clone()).run()
    }
}

pub(crate) fn generate_sample_batch_updates(
    num_checkpoints: usize,
    num_checkpoint_updates: usize,
    start_idx: usize,
) -> BatchCheckpointUpdates {
    let mut all_checkpoint_updates = Vec::new();
    for i in 0..num_checkpoints {
        let mut next_checkpoint_updates = CheckpointUpdates::new();
        for j in 0..num_checkpoint_updates {
            next_checkpoint_updates.push(StreamPoint::new(
                (i * num_checkpoint_updates + j).try_into().unwrap(),
                [(i + start_idx) as u8; 32],
            ));
        }
        assert!(check_sorted(&next_checkpoint_updates));
        all_checkpoint_updates.push(next_checkpoint_updates);
    }
    BatchCheckpointUpdates(all_checkpoint_updates)
}
