use super::{private_keys::generate_private_key, public_keys::generate_public_key};
use num_primes::Generator;
use num_traits::ToPrimitive;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct PublicKey {
    encryption_value: usize,
    modulus: usize,
}

#[derive(Debug)]
pub struct PrivateKey {
    decryption_value: usize,
    modulus: usize,
}

impl PrivateKey {
    pub fn new(decryption_value: usize, modulus: usize) -> Self {
        return PrivateKey {
            decryption_value,
            modulus,
        };
    }

    pub fn modulus(self: &Self) -> usize {
        self.modulus
    }

    pub fn decryption_value(self: &Self) -> usize {
        self.decryption_value
    }
}

impl PublicKey {
    pub fn new(encryption_value: usize, modulus: usize) -> Self {
        PublicKey {
            encryption_value,
            modulus,
        }
    }

    pub fn modulus(self: &Self) -> usize {
        self.modulus
    }

    pub fn encryption_value(self: &Self) -> usize {
        self.encryption_value
    }
}

pub struct PrimeBase {
    pub p: usize,
    pub q: usize,
    pub modulus: usize,
}

fn generate_base() -> PrimeBase {
    let p: usize = Generator::new_prime(8)
        .to_usize()
        .expect("Failed to format data in key creation");
    let q: usize = Generator::new_prime(8)
        .to_usize()
        .expect("Failed to format data in key creation");
    let modulus: usize = p * q;
    PrimeBase { p, q, modulus }
}

pub fn generate_keys() -> (PublicKey, PrivateKey) {
    let base: PrimeBase = generate_base();
    let public_key: (PublicKey, usize) = generate_public_key(&base);
    let private_key: PrivateKey = generate_private_key(&public_key.0, public_key.1, base.modulus);
    (public_key.0, private_key)
}
