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
