use crate::{CheckpointUpdates, StreamPoint};

pub fn init_logging(level: log::LevelFilter) {
    // Initialize logging
    let mut builder = env_logger::Builder::from_default_env();
    builder.format_timestamp(None);
    builder.filter_level(level);
    builder.try_init().unwrap();
}

// Test vector: All checkpoints update the same set of stream points
pub fn generate_sample_checkpoint_updates(
    num_checkpoints: usize,
    num_checkpoint_updates: usize,
) -> Vec<CheckpointUpdates> {
    let start_checkpoint_number = 0;
    let mut all_updates = Vec::new();
    let first_set = (0..num_checkpoint_updates)
        .map(|i| {
            StreamPoint::new_with_flag(
                i.try_into().unwrap(),
                [start_checkpoint_number as u8; 32],
                true,
            )
        })
        .collect();
    all_updates.push(first_set);
    for _ in 1..num_checkpoints {
        all_updates.push(
            (0..num_checkpoint_updates)
                .map(|i| {
                    StreamPoint::new_with_flag(
                        i.try_into().unwrap(),
                        [(start_checkpoint_number + i) as u8; 32],
                        false,
                    )
                })
                .collect(),
        );
    }
    all_updates
}
