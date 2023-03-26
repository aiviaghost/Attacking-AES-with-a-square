use crate::aes::{Block, RoundKey, AES128, BLOCK_SIZE};
use rand::{thread_rng, Rng};

pub fn crack_key(encryption_service: &AES128) -> [u8; BLOCK_SIZE] {
    let mut recovered_key = [0; BLOCK_SIZE];

    for i in 0..BLOCK_SIZE {
        let mut potential_bytes = crack_single_byte(encryption_service, i);
        while potential_bytes.len() > 1 {
            potential_bytes = crack_single_byte(encryption_service, i);
        }
        recovered_key[i] = potential_bytes[0];
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

fn crack_single_byte(encryption_service: &AES128, pos: usize) -> Vec<u8> {
    let enc_delta_set = setup(encryption_service);

    let mut potential_bytes = Vec::new();
    // let mut guessed_round_key = [[0u8; 4]; 4];
    // 'outer: for guess in 0..=255 {
    //     for i in 0..=255 {
    //         for j in 0..=255 {
    //             for k in 0..=255 {
    //                 for l in 0..=255 {
    //                     guessed_round_key[0][(pos + pos / 4) % 4] = i;
    //                     guessed_round_key[1][(pos + pos / 4 + 3) % 4] = j;
    //                     guessed_round_key[2][(pos + pos / 4 + 2) % 4] = k;
    //                     guessed_round_key[3][(pos + pos / 4 + 1) % 4] = l;
    //                     let guessed_state =
    //                         reverse_state(guess, pos, guessed_round_key, enc_delta_set);
    //                     if is_valid_guess(guessed_state) {
    //                         potential_bytes.push(guess);
    //                         if potential_bytes.len() == 2 {
    //                             break 'outer;
    //                         }
    //                     }
    //                 }
    //             }
    //         }
    //     }
    // }

    if potential_bytes.len() == 1 {
        println!("potential_bytes: {:?}", potential_bytes);
    }
    potential_bytes
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
        state = AES128::inv_shift_rows(state);
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
        let key = "sixteen byte key"
            .bytes()
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let num_rounds = 5;
        let aes = AES128::new(key, num_rounds);
        let enc_delta_set = setup(&aes);
        let round_keys = AES128::key_expansion(AES128::block_to_state(key), num_rounds);
        for pos in 0..1 {
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
