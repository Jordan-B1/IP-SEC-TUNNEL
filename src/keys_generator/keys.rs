use super::{private_keys::generate_private_key, public_keys::generate_public_key};
use num_primes::Generator;
use num_traits::ToPrimitive;
use serde::{Deserialize, Serialize};

/// Public key used in the RSA algorithm
///
/// This struct is used to store the public key used in the RSA algorithm
///
/// # Fields
/// - **encryption_value** - The value used to encrypt the data<br/>
/// - **modulus** - The modulus of the public key
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct PublicKey {
    encryption_value: usize,
    modulus: usize,
}

/// Private key used in the RSA algorithm
///
/// This struct is used to store the private key used in the RSA algorithm
///
/// # Fields
/// - **decryption_value** - The value used to decrypt the data<br/>
/// - **modulus** - The modulus of the private key
#[derive(Debug)]
pub struct PrivateKey {
    decryption_value: usize,
    modulus: usize,
}

impl PrivateKey {
    /// Create a new private key
    ///
    /// This function will create a new private key
    ///
    /// # Arguments
    /// decryption_value: **usize** - The value used to decrypt the data<br/>
    /// modulus: **usize** - The modulus of the private key
    ///
    /// # Returns
    /// **PrivateKey** - The private key created
    pub fn new(decryption_value: usize, modulus: usize) -> Self {
        return PrivateKey {
            decryption_value,
            modulus,
        };
    }

    /// Get the modulus
    ///
    /// This function will return the modulus of the private key
    ///
    /// # Returns
    /// **usize** - The modulus of the private key
    pub fn modulus(self: &Self) -> usize {
        self.modulus
    }

    /// Get the decryption value
    ///
    /// This function will return the decryption value of the private key
    ///
    /// # Returns
    /// **usize** - The decryption value of the private key
    pub fn decryption_value(self: &Self) -> usize {
        self.decryption_value
    }
}

impl PublicKey {
    /// Create a new public key
    ///
    /// This function will create a new public key
    ///
    /// # Arguments
    /// encryption_value: **usize** - The value used to encrypt the data<br/>
    /// modulus: **usize** - The modulus of the public key
    ///
    /// # Returns
    /// **PublicKey** - The public key created
    pub fn new(encryption_value: usize, modulus: usize) -> Self {
        PublicKey {
            encryption_value,
            modulus,
        }
    }

    /// Get the modulus
    ///
    /// This function will return the modulus of the public key
    ///
    /// # Returns
    /// **usize** - The modulus of the public key
    pub fn modulus(self: &Self) -> usize {
        self.modulus
    }

    /// Get the encryption value
    ///
    /// This function will return the encryption value of the public key
    ///
    /// # Returns
    /// **usize** - The encryption value of the public key
    pub fn encryption_value(self: &Self) -> usize {
        self.encryption_value
    }
}

/// Base for the RSA algorithm
///
/// This struct is used to store the base for the RSA algorithm
///
/// # Fields
/// - **p** - The first prime number<br/>
/// - **q** - The second prime number<br/>
/// - **modulus** - The modulus of the base
pub struct PrimeBase {
    pub p: usize,
    pub q: usize,
    pub modulus: usize,
}

/// Generate a base for the RSA algorithm
///
/// This function will generate a base for the RSA algorithm
///
/// # Returns
/// **PrimeBase** - The base generated
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

/// Generate a public and private key
///
/// Using the RSA algorithm, this function will generate a public and private key
///
/// # Returns
/// **(PublicKey, PrivateKey)** - The public and private key generated
pub fn generate_keys() -> (PublicKey, PrivateKey) {
    let base: PrimeBase = generate_base();
    let public_key: (PublicKey, usize) = generate_public_key(&base);
    let private_key: PrivateKey = generate_private_key(&public_key.0, public_key.1, base.modulus);
    (public_key.0, private_key)
}
