use num_integer::Integer;
use num_traits::ToPrimitive;

use super::keys::{PrimeBase, PublicKey};

fn generate_totient(base: &PrimeBase) -> usize {
    return (base.p - 1) * (base.q - 1);
}

pub fn generate_public_key(base: &PrimeBase) -> (PublicKey, usize) {
    let r: usize = generate_totient(base);
    let mut e: usize = 2;
    while e < r {
        if e.gcd(&r) == 1 {
            break;
        }
        e += 1;
    }
    let e: usize = e.to_usize().expect("Failed to format data in key creation");
    return (PublicKey::new(e, base.modulus), r);
}
