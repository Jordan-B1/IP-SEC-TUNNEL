use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::One;

use super::keys::{PrimeBase, PublicKey};

/// Generate the totient of a base
///
/// This function will generate the totient of a base
///
/// # Arguments
/// base: **&PrimeBase** - The base to generate the totient from<br/>
///
/// # Returns
/// **BigUint** - The totient of the base
fn generate_totient(base: &PrimeBase) -> BigUint {
    return (&base.p - BigUint::one()).lcm(&(&base.q - BigUint::one()));
}

/// Generate a public key
///
/// Using the RSA algorithm, this function will generate a public key
///
/// # Arguments
/// base: **&PrimeBase** - The base to generate the public key from
///
/// # Returns
/// **(PublicKey, BigUint)** - The public key generated and the value of the totient of the base
pub fn generate_public_key(base: &PrimeBase) -> (PublicKey, BigUint) {
    let r: BigUint = generate_totient(base);
    let mut e: BigUint = BigUint::from(2_u32);
    while e < r {
        if e.gcd(&r) == BigUint::one() {
            break;
        }
        e += BigUint::one();
    }
    // let e = BigUint::from(65537_u32);
    return (PublicKey::new(&e, &base.modulus), r);
}