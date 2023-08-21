use aes::{AES128, BLOCK_SIZE};
use attack::crack_key;
use rand::{thread_rng, Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

mod aes;
mod attack;

fn generate_secure_key() -> [u8; BLOCK_SIZE] {
    let mut key = [0; BLOCK_SIZE];
    ChaCha20Rng::from_rng(thread_rng()).unwrap().fill(&mut key);
    key
}

fn main() {
    unsafe {
        let secret_key = generate_secure_key();
        let aes = AES128::new(secret_key, 5);

        println!("{:?}", secret_key);

        let recovered_key = crack_key(&aes);

        println!("{:?}", recovered_key);

        if recovered_key == secret_key {
            println!("Key successfully recovered!");
        } else {
            println!("Failed to recover key!");
        }
    }
}
