use num_bigint::{BigUint, ToBigUint};

pub fn enigma(data: &Vec<usize>, exponent: usize, modulus: usize) -> Vec<usize> {
    data.iter()
        .map(|&byte| {
            let b: BigUint = BigUint::from(byte);
            let c = b.pow(exponent as u32) % modulus.to_biguint().unwrap();
            return c.to_u32_digits()[0] as usize;
        })
        .collect()
}
