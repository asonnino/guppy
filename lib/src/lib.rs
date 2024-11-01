use sha3::{Digest as OtherDigest, Sha3_256};

pub type Digest = [u8; 32];
pub type StreamID = u32;

pub type CheckpointUpdates = Vec<(StreamID, Digest)>;
pub type GlobalState = Vec<(StreamID, Digest)>;

#[sp1_derive::cycle_tracker]
pub fn compute_new_state(l: &CheckpointUpdates, v_prev: &GlobalState) -> GlobalState {
    let mut v_next = GlobalState::new();
    for (stream, existing_value) in v_prev {
        if let Some((_, new_value)) = l.iter().find(|(s, _)| s == stream) {
            v_next.push((*stream, *new_value));
        } else {
            v_next.push((*stream, *existing_value));
        }
    }
    v_next
}

// pub fn compute_new_state(l: &CheckpointUpdates, v_prev: &GlobalState) -> GlobalState {
//     let mut v_next = GlobalState::new();
//     for (stream, existing_value) in v_prev {
//         if let Some(new_value) = l.get(stream) {
//             v_next.push((*stream, *new_value));
//         } else {
//             v_next.push((*stream, *existing_value));
//         }
//     }
//     v_next
// }

#[sp1_derive::cycle_tracker]
pub fn compute_global_commitment(v: &GlobalState) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    for (stream, value) in v {
        hasher.update(stream.to_le_bytes());
        hasher.update(value);
    }
    hasher.finalize().into()
}

#[sp1_derive::cycle_tracker]
pub fn compute_local_commitment(l: &CheckpointUpdates, d_prev: &Digest) -> Digest {
    let mut hasher = Sha3_256::new();
    hasher.update(d_prev);
    for (stream, value) in l {
        hasher.update(stream.to_le_bytes());
        hasher.update(value);
    }
    hasher.finalize().into()
}
