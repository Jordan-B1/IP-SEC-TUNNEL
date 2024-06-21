use num_bigint::{BigUint, ToBigUint};

/// Apply the RSA algorithm
///
/// This function will encrypt or decrypt the data given as parameter using the RSA algorithm
///
/// # Arguments
/// data: **&Vec<usize>** - The data to encrypt/decypher<br/>
/// exponent: **usize** - The exponent to use for the operation<br/>
/// modulus: **usize** - The modulus to use for the operation
///
/// # Returns
/// **Vec<usize>** - The data encrypted/decrypted
pub fn enigma(data: &Vec<usize>, exponent: usize, modulus: usize) -> Vec<usize> {
    data.iter()
        .map(|&byte| {
            let b: BigUint = BigUint::from(byte);
            let c = b.pow(exponent as u32) % modulus.to_biguint().unwrap();
            return c.to_u32_digits()[0] as usize;
        })
        .collect()
}
