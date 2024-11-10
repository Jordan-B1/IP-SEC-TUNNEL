use num_bigint::BigUint;

use super::keys::{PrivateKey, PublicKey};

/// Generate a private key from a public key
///
/// Using the RSA algorithm, this function will generate a private key from a public key
///
/// # Arguments
/// public_key: **&PublicKey** - The public key to generate the private key from<br/>
/// r: **BigUint** - The value of the totient function of the public key modulus<br/>
/// modulus: **BigUint** - The value of the public key modulus
///
/// # Returns
/// **PrivateKey** - The private key generated from the public key
pub fn generate_private_key(public_key: &PublicKey, r: &BigUint, modulus: &BigUint) -> PrivateKey {
    let decryption: BigUint = public_key.encryption_value().modinv(&r).unwrap();
    return PrivateKey::new(&decryption, &modulus);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_private_key() {
        let public_key: PublicKey = PublicKey::new(&BigUint::from(17u32), &BigUint::from(3233u32));
        let result: PrivateKey =
            generate_private_key(&public_key, &BigUint::from(780u32), &BigUint::from(3233u32));
        assert_eq!(result.decryption_value(), BigUint::from(413u32));
        assert_eq!(result.modulus(), BigUint::from(3233u32));
    }
}
