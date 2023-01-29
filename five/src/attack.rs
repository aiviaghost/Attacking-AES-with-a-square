use crate::aes::AES128;

pub fn crack_key(encryption_service: &AES128) -> Vec<u8> {
    let mut recovered_key = vec![0; 16];

    for i in 0..16 {
        recovered_key[i] = brute_force_position(encryption_service, i);
    }

    recovered_key
}

fn brute_force_position(encryption_service: &AES128, pos: usize) -> u8 {
    0
}
