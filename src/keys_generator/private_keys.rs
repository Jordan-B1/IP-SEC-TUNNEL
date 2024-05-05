use super::keys::{PrivateKey, PublicKey};

pub fn generate_private_key(public_key: &PublicKey, r: usize, key_len: usize) -> PrivateKey {
    let mut decryption = (public_key.encryption_value() as isize % (-1)) as usize;
    decryption %= r;
    return PrivateKey::new(decryption, key_len);
}
