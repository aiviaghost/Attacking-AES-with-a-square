use std::arch::x86_64::{__m128i, _mm_extract_epi8, _mm_xor_si128};
use std::ops::{Index, IndexMut};

use std::time::Instant;

use crate::aes::{Block, RoundKey, AES128, BLOCK_SIZE};
use rand::{thread_rng, Rng};

use std::cmp::Ordering::{Equal, Greater, Less};

union SIMDBytes256 {
    bytes: [u8; 256],
    simd_vectors: [__m128i; 16],
}

impl SIMDBytes256 {
    fn new() -> Self {
        Self { bytes: [0; 256] }
    }
}

impl Index<usize> for SIMDBytes256 {
    type Output = u8;
    fn index<'a>(&'a self, i: usize) -> &'a u8 {
        unsafe { &self.bytes[i] }
    }
}

impl IndexMut<usize> for SIMDBytes256 {
    fn index_mut<'a>(&'a mut self, i: usize) -> &'a mut u8 {
        unsafe { &mut self.bytes[i] }
    }
}

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

        let start = Instant::now();
        let mut batch_count = 1;

        while candidates.peek().is_some() {
            let batch = candidates.by_ref().take(1 << 20).collect();
            let maybe = crack_given_candidates(encryption_service, pos, batch);
            if let Some(x) = maybe {
                potential_bytes.push(x);
            }
            println!(
                "Batch {batch_count}: Average batch time = {:.4}s => ETA = {:.4} days",
                start.elapsed().as_secs_f64() / batch_count as f64,
                ((start.elapsed().as_secs_f64() / batch_count as f64) * ((1 << 20) as f64))
                    / (3600f64 * 24f64)
            );
            batch_count += 1;
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

    let mut new_candidates = vec![];

    for (guess, candidate) in candidates {
        let guessed_state = reverse_state(guess, pos, candidate, enc_delta_set);
        if is_valid_guess(guessed_state) {
            new_candidates.push((guess, candidate));
        }
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
) -> SIMDBytes256 {
    let mut reversed_bytes = SIMDBytes256::new();
    let mut guessed_key = [0; BLOCK_SIZE];
    guessed_key[pos] = guess;
    let guessed_key = AES128::block_to_state(guessed_key);
    for (i, enc) in enc_delta_set.iter().enumerate() {
        let mut state = AES128::block_to_state(*enc);
        state = AES128::inv_add_round_key(state, guessed_round_key);
        state = AES128::inv_shift_rows(state);
        state = AES128::inv_sub_bytes(state);
        state = AES128::inv_mix_columns(state);
        state = AES128::inv_add_round_key(state, guessed_key);
        // state = AES128::inv_shift_rows(state);
        state = AES128::inv_sub_bytes(state);
        let state = AES128::state_to_block(state);
        reversed_bytes[i] = state[pos];
    }
    reversed_bytes
}

#[inline]
unsafe fn m128i_to_u8x16(vector: __m128i) -> [u8; 16] {
    [
        _mm_extract_epi8(vector, 0) as u8,
        _mm_extract_epi8(vector, 1) as u8,
        _mm_extract_epi8(vector, 2) as u8,
        _mm_extract_epi8(vector, 3) as u8,
        _mm_extract_epi8(vector, 4) as u8,
        _mm_extract_epi8(vector, 5) as u8,
        _mm_extract_epi8(vector, 6) as u8,
        _mm_extract_epi8(vector, 7) as u8,
        _mm_extract_epi8(vector, 8) as u8,
        _mm_extract_epi8(vector, 9) as u8,
        _mm_extract_epi8(vector, 10) as u8,
        _mm_extract_epi8(vector, 11) as u8,
        _mm_extract_epi8(vector, 12) as u8,
        _mm_extract_epi8(vector, 13) as u8,
        _mm_extract_epi8(vector, 14) as u8,
        _mm_extract_epi8(vector, 15) as u8,
    ]
}

unsafe fn is_valid_guess(recovered_bytes: SIMDBytes256) -> bool {
    let mut curr = recovered_bytes.simd_vectors[0];
    for i in 1..16 {
        curr = _mm_xor_si128(curr, recovered_bytes.simd_vectors[i]);
    }
    m128i_to_u8x16(curr).iter().fold(0, |acc, curr| acc ^ curr) == 0
}

#[cfg(test)]
mod tests {
    use crate::aes::AES128;

    use super::{is_valid_guess, reverse_state, setup, SIMDBytes256};

    #[test]
    fn test_is_valid_guess() {
        unsafe {
            let xs = SIMDBytes256 {
                bytes: (0..=255).collect::<Vec<_>>().try_into().unwrap(),
            };
            assert!(is_valid_guess(xs));
        }
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
