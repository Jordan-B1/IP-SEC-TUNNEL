use num_bigint::BigUint;

/// Apply the RSA algorithm
///
/// This function will encrypt or decrypt the data given as parameter using the RSA algorithm
///
/// # Arguments
/// data: **&Vec<u8>** - The data to cypher/decypher<br/>
/// exponent: **&BigUint** - The exponent to use for the operation<br/>
/// modulus: **&BigUint** - The modulus to use for the operation
///
/// # Returns
/// **Vec<usize>** - The data encrypted/decrypted
pub fn enigma(data: &Vec<u8>, exponent: &BigUint, modulus: &BigUint) -> Vec<u8> {
    let mut chunked_data = data.chunks(256);
    let mut current_chunk = chunked_data.next();
    let mut res: Vec<Vec<u8>> = vec![];

    while current_chunk.is_some() {
        let m: BigUint = BigUint::from_bytes_be(current_chunk.unwrap());
        m.modpow(exponent, modulus).to_bytes_be();
        res.push(m.to_bytes_be());
        current_chunk = chunked_data.next();
    }

    res.into_iter().flatten().collect()
}

#[cfg(test)]
mod tests {
    use crate::keys_generator::keys::generate_keys;

    use super::*;

    #[test]
    fn test_enigma() {
        let double_keys = generate_keys();
        let data = "Hello";
        let c: Vec<u8> = enigma(
            &data.as_bytes().to_vec(),
            &double_keys.0.encryption_value(),
            &double_keys.0.modulus(),
        );
        let p = enigma(
            &c,
            &double_keys.1.decryption_value(),
            &double_keys.1.modulus(),
        );
        println!("{:?} and {:?}", p, data.as_bytes().to_vec());
        assert_eq!(data.as_bytes().to_vec(), p);
    }
}
