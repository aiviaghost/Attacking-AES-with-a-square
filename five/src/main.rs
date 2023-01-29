use aes::{AES128, BLOCK_SIZE};
use attack::crack_key;
use rand::{thread_rng, Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

mod aes;
mod attack;
mod utils;

fn generate_secure_key() -> [u8; BLOCK_SIZE] {
    let mut key = [0; BLOCK_SIZE];
    let mut rng = ChaCha20Rng::from_rng(thread_rng()).unwrap();
    rng.fill(&mut key);
    key
}

fn main() {
    let secret_key = generate_secure_key();
    let aes = AES128::new(secret_key.clone(), 5);

    let recovered_key = crack_key(&aes);

    println!("{:?}", secret_key);
    println!("{:?}", recovered_key);

    if recovered_key == secret_key {
        println!("Key successfilly recovered!");
    } else {
        println!("Failed to recover key!");
    }
}
