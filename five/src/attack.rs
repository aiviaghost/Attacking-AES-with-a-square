use crate::aes::{AES128, BLOCK_SIZE};

pub fn crack_key(encryption_service: &AES128) -> [u8; BLOCK_SIZE] {
    let mut recovered_key = [0; BLOCK_SIZE];

    for i in 0..BLOCK_SIZE {
        recovered_key[i] = crack_single_byte(encryption_service, i);
    }

    recovered_key
}

fn crack_single_byte(encryption_service: &AES128, pos: usize) -> u8 {
    0
}
