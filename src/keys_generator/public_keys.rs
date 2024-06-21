use num_integer::Integer;
use num_traits::ToPrimitive;

use super::keys::{PrimeBase, PublicKey};

/// Generate the totient of a base
///
/// This function will generate the totient of a base
///
/// # Arguments
/// base: **&PrimeBase** - The base to generate the totient from<br/>
///
/// # Returns
/// **usize** - The totient of the base
fn generate_totient(base: &PrimeBase) -> usize {
    return (base.p - 1) * (base.q - 1);
}

/// Generate a public key
///
/// Using the RSA algorithm, this function will generate a public key
///
/// # Arguments
/// base: **&PrimeBase** - The base to generate the public key from
///
/// # Returns
/// **(PublicKey, usize)** - The public key generated and the value of the totient of the base
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
