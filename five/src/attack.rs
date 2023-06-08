use std::time::Instant;

use crate::aes::{Block, RoundKey, AES128, BLOCK_SIZE};
use rand::{thread_rng, Rng};

use std::cmp::Ordering::{Equal, Greater, Less};

#[target_feature(enable = "avx2,aes")]
pub unsafe fn crack_key(encryption_service: &AES128) -> [u8; BLOCK_SIZE] {
    let mut recovered_key = [0; BLOCK_SIZE];

    for pos in 0..BLOCK_SIZE {
        let mut candidates = (0..1u64 << 40)
            .map(|mask| {
                let guess = mask as u8;

                let mut guessed_round_key = [0; BLOCK_SIZE];
                let col = (pos & 3) << 2;
                guessed_round_key[col + 0] = (mask >> 8) as u8;
                guessed_round_key[col + 1] = (mask >> 16) as u8;
                guessed_round_key[col + 2] = (mask >> 24) as u8;
                guessed_round_key[col + 3] = (mask >> 32) as u8;
                let guessed_round_key =
                    AES128::shift_rows(AES128::block_to_state(guessed_round_key));

                (guess, guessed_round_key)
            })
            .peekable();

        let mut potential_bytes = vec![];

        let mut start = Instant::now();
        let mut batch_count = 0;

        let batch_size = 1u64 << 20;

        while candidates.peek().is_some() {
            let batch = candidates.by_ref().take(batch_size as usize).collect();
            let maybe = crack_given_candidates(encryption_service, pos, batch);
            if let Some(x) = maybe {
                potential_bytes.push(x);
            }
            println!(
                "Batch {batch_count} took {}s => ETA = {} days",
                start.elapsed().as_secs_f32(),
                (start.elapsed().as_secs_f64() * ((1u64 << 40) / batch_size) as f64)
                    / (3600f64 * 24f64)
            );
            batch_count += 1;
            start = Instant::now();
        }

        let correct_byte = crack_given_candidates(encryption_service, pos, potential_bytes)
            .unwrap()
            .0;

        recovered_key[pos] = correct_byte;
    }

    recovered_key
}

fn gen_random_block() -> Block {
    let mut block = [0; BLOCK_SIZE];
    thread_rng().fill(&mut block);
    block
}

#[target_feature(enable = "avx2,aes")]
unsafe fn setup(encryption_service: &AES128) -> [Block; 256] {
    let mut delta_set = [gen_random_block(); 256];
    for i in 0..256 {
        delta_set[i][0] = i as u8;
    }
    delta_set.map(|block| encryption_service.encrypt(block))
}

#[target_feature(enable = "avx2,aes")]
unsafe fn crack_given_candidates(
    encryption_service: &AES128,
    pos: usize,
    candidates: Vec<(u8, RoundKey)>,
) -> Option<(u8, RoundKey)> {
    let enc_delta_set = setup(encryption_service);

    let mut new_candidates = candidates;

    for _ in 0..3 {
        let mut next = vec![];
        for (guess, candidate) in new_candidates {
            let guessed_state = reverse_state(guess, pos, candidate, enc_delta_set);
            if is_valid_guess(guessed_state) {
                next.push((guess, candidate));
            }
        }
        new_candidates = next;
    }

    match new_candidates.len().cmp(&1) {
        Equal => Some(new_candidates[0]),
        Greater => crack_given_candidates(encryption_service, pos, new_candidates),
        Less => None,
    }
}

#[target_feature(enable = "avx2,aes")]
unsafe fn reverse_state(
    guess: u8,
    pos: usize,
    guessed_round_key: RoundKey,
    enc_delta_set: [Block; 256],
) -> Vec<u8> {
    let mut reversed_bytes = Vec::new();
    let mut guessed_key = [0; BLOCK_SIZE];
    guessed_key[pos] = guess;
    let guessed_key = AES128::block_to_state(guessed_key);
    for enc in enc_delta_set {
        let mut state = AES128::block_to_state(enc);
        state = AES128::inv_add_round_key(state, guessed_round_key);
        state = AES128::inv_shift_rows(state);
        state = AES128::inv_sub_bytes(state);
        state = AES128::inv_mix_columns(state);
        state = AES128::inv_add_round_key(state, guessed_key);
        // state = AES128::inv_shift_rows(state);
        state = AES128::inv_sub_bytes(state);
        let state = AES128::state_to_block(state);
        reversed_bytes.push(state[pos]);
    }
    reversed_bytes
}

fn is_valid_guess(recovered_bytes: Vec<u8>) -> bool {
    recovered_bytes.iter().fold(0, |curr, next| curr ^ next) == 0
}

#[cfg(test)]
mod tests {
    use crate::aes::AES128;

    use super::{is_valid_guess, reverse_state, setup};

    #[test]
    fn test_is_valid_guess() {
        assert!(is_valid_guess((0..=255).collect()));
    }

    #[test]
    fn test_reverse_state() {
        unsafe {
            let key = "sixteen byte key"
                .bytes()
                .collect::<Vec<_>>()
                .try_into()
                .unwrap();
            let num_rounds = 5;
            let aes = AES128::new(key, num_rounds);
            let enc_delta_set = setup(&aes);
            let round_keys = AES128::key_expansion(AES128::block_to_state(key));
            for pos in 0..16 {
                let key_guess =
                    AES128::state_to_block(AES128::inv_mix_columns(round_keys[num_rounds - 1]))
                        [pos];
                assert!(is_valid_guess(reverse_state(
                    key_guess,
                    pos,
                    round_keys[num_rounds],
                    enc_delta_set
                )))
            }
        }
    }
}
