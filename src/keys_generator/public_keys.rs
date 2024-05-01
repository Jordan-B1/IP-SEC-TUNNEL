use crate::keys_generator::maths::gcd;

use super::keys::{PrimeBase, PublicKey};

const E_VALUES: [usize; 4] = [3, 5, 17, 65537];

fn generate_totient(base: &PrimeBase) -> usize {
    return (base.p * base.q) / gcd::compute_gcd(base.p, base.q);
}

pub fn generate_public_key(base: &PrimeBase) -> (PublicKey, usize) {
    let r = generate_totient(base);
    let e = std::cmp::Reverse(E_VALUES)
        .0
        .iter()
        .position(|&a| a < r)
        .unwrap();

    return (PublicKey::new(E_VALUES[e], base.p * base.q), r);
}
