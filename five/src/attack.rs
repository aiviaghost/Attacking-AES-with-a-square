use crate::aes::{Block, AES128, BLOCK_SIZE};

pub fn crack_key(encryption_service: &AES128) -> [u8; BLOCK_SIZE] {
    let mut recovered_key = [0; BLOCK_SIZE];

    for i in 0..BLOCK_SIZE {
        recovered_key[i] = crack_single_byte(encryption_service, i);
    }

    recovered_key
}

fn setup(encryption_service: &AES128) -> [Block; 256] {
    let mut delta_set = [[0u8; BLOCK_SIZE]; 256];
    for i in 0..256 {
        delta_set[i][0] = i as u8;
    }
    delta_set.map(|block| encryption_service.encrypt(block))
}

fn crack_single_byte(encryption_service: &AES128, pos: usize) -> u8 {
    let enc_delta_set = setup(encryption_service);

    0
}
