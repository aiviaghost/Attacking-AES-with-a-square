mod aes;

use aes::AES128;
fn main() {
    let enc = AES128::new(vec![0; 16]);
}
