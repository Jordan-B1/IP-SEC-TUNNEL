use num_bigint::BigInt;

use super::keys::{PrivateKey, PublicKey};

/// Generate a private key from a public key
///
/// Using the RSA algorithm, this function will generate a private key from a public key
///
/// # Arguments
/// public_key: **&PublicKey** - The public key to generate the private key from<br/>
/// r: **usize** - The value of the totient function of the public key modulus<br/>
/// modulus: **usize** - The value of the public key modulus
///
/// # Returns
/// **PrivateKey** - The private key generated from the public key
pub fn generate_private_key(public_key: &PublicKey, r: usize, modulus: usize) -> PrivateKey {
    let decryption: usize = BigInt::from(public_key.encryption_value())
        .modinv(&BigInt::from(r))
        .unwrap()
        .to_u32_digits()
        .1[0] as usize;
    return PrivateKey::new(decryption, modulus);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_private_key() {
        let public_key: PublicKey = PublicKey::new(17, 3233);
        let result: PrivateKey = generate_private_key(&public_key, 780, 3233);
        assert_eq!(result.decryption_value(), 413);
        assert_eq!(result.modulus(), 3233);
    }
}
