use crate::aes::{Block, RoundKey, AES128, BLOCK_SIZE};
use rand::{thread_rng, Rng};

pub fn crack_key(encryption_service: &AES128) -> [u8; BLOCK_SIZE] {
    let mut recovered_key = [0; BLOCK_SIZE];

    for pos in 0..BLOCK_SIZE {
        let mut candidates = (0..1u64 << 40)
            .map(|mask| {
                let mut guessed_round_key = [[0; 4]; 4];

                let guess = (mask & 0b11111111) as u8;

                guessed_round_key[0][(pos + pos / 4) % 4] = ((mask >> 8) & 0b11111111) as u8;
                guessed_round_key[1][(pos + pos / 4 + 3) % 4] = ((mask >> 16) & 0b11111111) as u8;
                guessed_round_key[2][(pos + pos / 4 + 2) % 4] = ((mask >> 24) & 0b11111111) as u8;
                guessed_round_key[3][(pos + pos / 4 + 1) % 4] = ((mask >> 32) & 0b11111111) as u8;

                (guess, guessed_round_key)
            })
            .peekable();

        let mut potential_bytes = vec![];

        while candidates.peek().is_some() {
            let batch = candidates.by_ref().take(1 << 20).collect();
            let maybe = crack_given_candidates(encryption_service, pos, batch);
            if maybe.is_some() {
                potential_bytes.push(maybe.unwrap());
            }
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

fn setup(encryption_service: &AES128) -> [Block; 256] {
    let mut delta_set: [Block; 256] = [gen_random_block(); 256];
    for i in 0..256 {
        delta_set[i][0] = i as u8;
    }
    delta_set.map(|block| encryption_service.encrypt(block))
}

fn crack_given_candidates(
    encryption_service: &AES128,
    pos: usize,
    candidates: Vec<(u8, RoundKey)>,
) -> Option<(u8, RoundKey)> {
    let enc_delta_set = setup(encryption_service);

    let mut new_candidates = vec![];

    for (guess, candidate) in candidates {
        let guessed_state = reverse_state(guess, pos, candidate, enc_delta_set);
        if is_valid_guess(guessed_state) {
            new_candidates.push((guess, candidate));
        }
    }

    if new_candidates.len() == 1 {
        Some(new_candidates[0])
    } else if new_candidates.len() > 1 {
        crack_given_candidates(encryption_service, pos, new_candidates)
    } else {
        None
    }
}

fn reverse_state(
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
        reversed_bytes.push(state[pos / 4][pos % 4]);
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
        let key = "sixteen byte key"
            .bytes()
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let num_rounds = 5;
        let aes = AES128::new(key, num_rounds);
        let enc_delta_set = setup(&aes);
        let round_keys = AES128::key_expansion(AES128::block_to_state(key), num_rounds);
        for pos in 0..16 {
            let key_guess =
                AES128::state_to_block(AES128::inv_mix_columns(round_keys[num_rounds - 1]))[pos];
            assert!(is_valid_guess(reverse_state(
                key_guess,
                pos,
                round_keys[num_rounds],
                enc_delta_set
            )))
        }
    }
}
