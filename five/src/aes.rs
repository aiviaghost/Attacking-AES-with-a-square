use std::arch::x86_64::{
    __m128i, _mm_aesdec_si128, _mm_aesdeclast_si128, _mm_aesenc_si128, _mm_aesenclast_si128,
    _mm_aeskeygenassist_si128, _mm_extract_epi8, _mm_set_epi8, _mm_shuffle_epi32, _mm_shuffle_epi8,
    _mm_slli_si128, _mm_xor_si128,
};

pub const BLOCK_SIZE: usize = 16;

union U8x16 {
    vector: __m128i,
    bytes: [i8; 16],
}

union U32x4 {
    vector: __m128i,
    bytes: [i32; 4],
}

const ZERO: __m128i = unsafe { (U8x16 { bytes: [0; 16] }).vector };
const ISOLATE_SBOX_MASK: __m128i = unsafe {
    (U32x4 {
        bytes: [0x070A0D00, 0x0B0E0104, 0x0F020508, 0x0306090C],
    })
    .vector
};
const ISOLATE_SROWS_MASK: __m128i = unsafe {
    (U32x4 {
        bytes: [0x0F0A0500, 0x030E0904, 0x07020D08, 0x0B06010C],
    })
    .vector
};

pub type Block = [u8; BLOCK_SIZE];
type State = __m128i; // [[u8; 4]; 4];
pub type RoundKey = __m128i; // [[u8; 4]; 4];

pub struct AES128 {
    round_keys: Vec<RoundKey>,
    num_rounds: usize,
}

impl AES128 {
    pub unsafe fn new(key: [u8; BLOCK_SIZE], num_rounds: usize) -> Self {
        Self {
            round_keys: Self::key_expansion(Self::block_to_state(key)),
            num_rounds,
        }
    }

    #[target_feature(enable = "avx2")]
    unsafe fn aes_128_assist(temp1: __m128i, temp2: __m128i) -> __m128i {
        let temp2 = _mm_shuffle_epi32(temp2, 0xff);
        let mut temp3 = _mm_slli_si128(temp1, 0x4);
        let mut temp1 = _mm_xor_si128(temp1, temp3);
        temp3 = _mm_slli_si128(temp3, 0x4);
        temp1 = _mm_xor_si128(temp1, temp3);
        temp3 = _mm_slli_si128(temp3, 0x4);
        temp1 = _mm_xor_si128(temp1, temp3);
        temp1 = _mm_xor_si128(temp1, temp2);
        temp1
    }

    #[target_feature(enable = "avx2")]
    pub unsafe fn key_expansion(key: RoundKey) -> Vec<RoundKey> {
        let mut round_keys = vec![];

        let mut temp1 = key;
        round_keys.push(temp1);
        let mut temp2 = _mm_aeskeygenassist_si128(temp1, 0x1);
        temp1 = Self::aes_128_assist(temp1, temp2);
        round_keys.push(temp1);
        temp2 = _mm_aeskeygenassist_si128(temp1, 0x2);
        temp1 = Self::aes_128_assist(temp1, temp2);
        round_keys.push(temp1);
        temp2 = _mm_aeskeygenassist_si128(temp1, 0x4);
        temp1 = Self::aes_128_assist(temp1, temp2);
        round_keys.push(temp1);
        temp2 = _mm_aeskeygenassist_si128(temp1, 0x8);
        temp1 = Self::aes_128_assist(temp1, temp2);
        round_keys.push(temp1);
        temp2 = _mm_aeskeygenassist_si128(temp1, 0x10);
        temp1 = Self::aes_128_assist(temp1, temp2);
        round_keys.push(temp1);
        temp2 = _mm_aeskeygenassist_si128(temp1, 0x20);
        temp1 = Self::aes_128_assist(temp1, temp2);
        round_keys.push(temp1);
        temp2 = _mm_aeskeygenassist_si128(temp1, 0x40);
        temp1 = Self::aes_128_assist(temp1, temp2);
        round_keys.push(temp1);
        temp2 = _mm_aeskeygenassist_si128(temp1, 0x80);
        temp1 = Self::aes_128_assist(temp1, temp2);
        round_keys.push(temp1);
        temp2 = _mm_aeskeygenassist_si128(temp1, 0x1b);
        temp1 = Self::aes_128_assist(temp1, temp2);
        round_keys.push(temp1);
        temp2 = _mm_aeskeygenassist_si128(temp1, 0x36);
        temp1 = Self::aes_128_assist(temp1, temp2);
        round_keys.push(temp1);

        round_keys
    }

    #[target_feature(enable = "avx2")]
    unsafe fn sub_bytes(state: State) -> State {
        let res = _mm_shuffle_epi8(state, ISOLATE_SBOX_MASK);
        _mm_aesenclast_si128(res, ZERO)
    }

    #[target_feature(enable = "avx2")]
    pub unsafe fn inv_sub_bytes(state: State) -> State {
        let res = _mm_shuffle_epi8(state, ISOLATE_SROWS_MASK);
        _mm_aesdeclast_si128(res, ZERO)
    }

    #[target_feature(enable = "avx2")]
    unsafe fn shift_rows(state: State) -> State {
        _mm_shuffle_epi8(state, ISOLATE_SROWS_MASK)
    }

    #[target_feature(enable = "avx2")]
    pub unsafe fn inv_shift_rows(state: State) -> State {
        _mm_shuffle_epi8(state, ISOLATE_SBOX_MASK)
    }

    #[target_feature(enable = "avx2")]
    unsafe fn mix_columns(state: State) -> State {
        let res = _mm_aesdeclast_si128(state, ZERO);
        _mm_aesenc_si128(res, ZERO)
    }

    #[target_feature(enable = "avx2")]
    pub unsafe fn inv_mix_columns(state: State) -> State {
        let res = _mm_aesenclast_si128(state, ZERO);
        _mm_aesdec_si128(res, ZERO)
    }

    #[target_feature(enable = "avx2")]
    unsafe fn add_round_key(state: State, round_key: RoundKey) -> State {
        _mm_xor_si128(state, round_key)
    }

    #[target_feature(enable = "avx2")]
    pub unsafe fn inv_add_round_key(state: State, round_key: RoundKey) -> State {
        Self::add_round_key(state, round_key)
    }

    #[target_feature(enable = "avx2")]
    pub unsafe fn block_to_state(block: Block) -> State {
        _mm_set_epi8(
            block[15] as i8,
            block[14] as i8,
            block[13] as i8,
            block[12] as i8,
            block[11] as i8,
            block[10] as i8,
            block[9] as i8,
            block[8] as i8,
            block[7] as i8,
            block[6] as i8,
            block[5] as i8,
            block[4] as i8,
            block[3] as i8,
            block[2] as i8,
            block[1] as i8,
            block[0] as i8,
        )
    }

    #[target_feature(enable = "avx2")]
    pub unsafe fn state_to_block(state: State) -> Block {
        [
            _mm_extract_epi8(state, 0) as u8,
            _mm_extract_epi8(state, 1) as u8,
            _mm_extract_epi8(state, 2) as u8,
            _mm_extract_epi8(state, 3) as u8,
            _mm_extract_epi8(state, 4) as u8,
            _mm_extract_epi8(state, 5) as u8,
            _mm_extract_epi8(state, 6) as u8,
            _mm_extract_epi8(state, 7) as u8,
            _mm_extract_epi8(state, 8) as u8,
            _mm_extract_epi8(state, 9) as u8,
            _mm_extract_epi8(state, 10) as u8,
            _mm_extract_epi8(state, 11) as u8,
            _mm_extract_epi8(state, 12) as u8,
            _mm_extract_epi8(state, 13) as u8,
            _mm_extract_epi8(state, 14) as u8,
            _mm_extract_epi8(state, 15) as u8,
        ]
    }

    #[target_feature(enable = "avx2")]
    pub unsafe fn encrypt(&self, msg: Block) -> Block {
        let msg = Self::block_to_state(msg);

        let mut ct = Self::add_round_key(msg, self.round_keys[0]);
        for i in 1..self.num_rounds {
            ct = Self::add_round_key(
                Self::mix_columns(Self::shift_rows(Self::sub_bytes(ct))),
                self.round_keys[i],
            );
        }

        Self::state_to_block(Self::add_round_key(
            Self::shift_rows(Self::sub_bytes(ct)),
            self.round_keys[self.num_rounds],
        ))
    }

    #[target_feature(enable = "avx2")]
    pub unsafe fn decrypt(&self, enc_msg: Block) -> Block {
        let enc_msg = Self::block_to_state(enc_msg);

        let mut pt = Self::inv_sub_bytes(Self::inv_shift_rows(Self::inv_add_round_key(
            enc_msg,
            self.round_keys[self.num_rounds],
        )));
        for i in (1..self.num_rounds).rev() {
            pt = Self::inv_sub_bytes(Self::inv_shift_rows(Self::inv_mix_columns(
                Self::inv_add_round_key(pt, self.round_keys[i]),
            )));
        }

        Self::state_to_block(Self::inv_add_round_key(pt, self.round_keys[0]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_hex(hex: &str) -> Block {
        (0..hex.len())
            .step_by(2)
            .flat_map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }

    #[test]
    fn test_key_expansion() {
        unsafe {
            let original_key =
                AES128::block_to_state(decode_hex("2b7e151628aed2a6abf7158809cf4f3c"));
            let expected: Vec<_> = [
                "2b7e151628aed2a6abf7158809cf4f3c",
                "a0fafe1788542cb123a339392a6c7605",
                "f2c295f27a96b9435935807a7359f67f",
                "3d80477d4716fe3e1e237e446d7a883b",
                "ef44a541a8525b7fb671253bdb0bad00",
                "d4d1c6f87c839d87caf2b8bc11f915bc",
                "6d88a37a110b3efddbf98641ca0093fd",
                "4e54f70e5f5fc9f384a64fb24ea6dc4f",
                "ead27321b58dbad2312bf5607f8d292f",
                "ac7766f319fadc2128d12941575c006e",
                "d014f9a8c9ee2589e13f0cc8b6630ca6",
            ]
            .iter()
            .map(|s| decode_hex(s))
            .collect();

            assert_eq!(
                AES128::key_expansion(original_key)
                    .iter()
                    .map(|x| AES128::state_to_block(*x))
                    .collect::<Vec<_>>(),
                expected
            );
        }
    }

    #[test]
    fn test_shift_rows() {
        unsafe {
            let res = AES128::state_to_block(AES128::shift_rows(AES128::block_to_state(
                decode_hex("637c777bf26b6fc53001672bfed7ab76"),
            )));
            let expected = decode_hex("636b6776f201ab7b30d777c5fe7c6f2b");
            assert_eq!(res, expected)
        }
    }

    #[test]
    fn test_inv_shift_rows() {
        unsafe {
            let res = AES128::state_to_block(AES128::inv_shift_rows(AES128::block_to_state(
                decode_hex("636b6776f201ab7b30d777c5fe7c6f2b"),
            )));
            let expected = decode_hex("637c777bf26b6fc53001672bfed7ab76");
            assert_eq!(res, expected)
        }
    }

    #[test]
    fn test_sub_bytes() {
        unsafe {
            let res = AES128::state_to_block(AES128::sub_bytes(AES128::block_to_state(
                decode_hex("000102030405060708090a0b0c0d0e0f"),
            )));
            let expected = decode_hex("637c777bf26b6fc53001672bfed7ab76");
            assert_eq!(res, expected)
        }
    }

    #[test]
    fn test_inv_sub_bytes() {
        unsafe {
            let res = AES128::state_to_block(AES128::inv_sub_bytes(AES128::block_to_state(
                decode_hex("637c777bf26b6fc53001672bfed7ab76"),
            )));
            let expected = decode_hex("000102030405060708090a0b0c0d0e0f");
            assert_eq!(res, expected)
        }
    }

    #[test]
    fn test_mix_columns() {
        unsafe {
            let res = AES128::state_to_block(AES128::mix_columns(AES128::block_to_state(
                decode_hex("636b6776f201ab7b30d777c5fe7c6f2b"),
            )));
            let expected = decode_hex("6a6a5c452c6d3351b0d95d61279c215c");
            assert_eq!(res, expected)
        }
    }

    #[test]
    fn test_inv_mix_columns() {
        unsafe {
            let res = AES128::state_to_block(AES128::inv_mix_columns(AES128::block_to_state(
                decode_hex("6a6a5c452c6d3351b0d95d61279c215c"),
            )));
            let expected = decode_hex("636b6776f201ab7b30d777c5fe7c6f2b");
            assert_eq!(res, expected)
        }
    }

    #[test]
    fn test_add_round_key() {
        unsafe {
            let res = AES128::state_to_block(AES128::add_round_key(
                AES128::block_to_state(decode_hex("6a6a5c452c6d3351b0d95d61279c215c")),
                AES128::block_to_state(decode_hex("d6aa74fdd2af72fadaa678f1d6ab76fe")),
            ));
            let expected = decode_hex("bcc028b8fec241ab6a7f2590f13757a2");
            assert_eq!(res, expected)
        }
    }

    #[test]
    fn test_inv_add_round_key() {
        unsafe {
            let res = AES128::state_to_block(AES128::inv_add_round_key(
                AES128::block_to_state(decode_hex("bcc028b8fec241ab6a7f2590f13757a2")),
                AES128::block_to_state(decode_hex("d6aa74fdd2af72fadaa678f1d6ab76fe")),
            ));
            let expected = decode_hex("6a6a5c452c6d3351b0d95d61279c215c");
            assert_eq!(res, expected)
        }
    }

    #[test]
    fn test_full_round() {
        unsafe {
            let initial_state =
                AES128::block_to_state(decode_hex("000102030405060708090a0b0c0d0e0f"));
            let after_sub_bytes = AES128::sub_bytes(initial_state);
            let after_shift_rows = AES128::shift_rows(after_sub_bytes);
            let after_mix_columns = AES128::mix_columns(after_shift_rows);
            let res = AES128::state_to_block(AES128::add_round_key(
                after_mix_columns,
                AES128::block_to_state(decode_hex("d6aa74fdd2af72fadaa678f1d6ab76fe")),
            ));
            let expected = decode_hex("bcc028b8fec241ab6a7f2590f13757a2");
            assert_eq!(res, expected)
        }
    }

    #[test]
    fn test_encrypt() {
        unsafe {
            let aes = AES128::new(decode_hex("2b7e151628aed2a6abf7158809cf4f3c"), 10);
            let msg = "theblockbreakers"
                .bytes()
                .collect::<Vec<_>>()
                .try_into()
                .unwrap();
            let expected = decode_hex("c69f25d0025a9ef32393f63e2f05b747");
            assert_eq!(aes.encrypt(msg), expected)
        }
    }

    #[test]
    fn test_decrypt() {
        unsafe {
            let aes = AES128::new(decode_hex("2b7e151628aed2a6abf7158809cf4f3c"), 10);
            let enc_msg = "c69f25d0025a9ef32393f63e2f05b747";
            let expected: Block = "theblockbreakers"
                .bytes()
                .collect::<Vec<_>>()
                .try_into()
                .unwrap();
            assert_eq!(aes.decrypt(decode_hex(enc_msg)), expected)
        }
    }
}
