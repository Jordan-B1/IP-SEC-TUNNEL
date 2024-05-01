use super::{private_keys::generate_private_key, public_keys::generate_public_key};
use primes::{PrimeSet, Sieve};
use rand::{rngs::ThreadRng, seq::IteratorRandom};
use serde::{Deserialize, Serialize};


#[derive(Serialize, Deserialize, Debug)]
pub struct PublicKey
{
    encryption_value: usize,
    key_len: usize,
}

pub struct PrivateKey
{
    decryption_value: usize,
    key_len: usize,
}

impl PrivateKey
{
    pub fn new(decryption_value: usize, key_len: usize) -> Self
    {
        return PrivateKey {
            decryption_value,
            key_len
        };
    }

    pub fn key_len(self: &Self) -> usize
    {
        return self.key_len;
    }

    pub fn decryption_value(self: &Self) -> usize
    {
        return self.decryption_value;
    }
}

impl PublicKey
{
    pub fn new(encryption_value: usize, key_len: usize) -> Self
    {
        return PublicKey {
            encryption_value,
            key_len
        };
    }

    pub fn key_len(self: &Self) -> usize
    {
        return self.key_len;
    }

    pub fn encryption_value(self: &Self) -> usize
    {
        return self.encryption_value;
    }
}

pub struct PrimeBase {
    pub p: usize,
    pub q: usize,
}

fn generate_base() -> PrimeBase {
    let mut p: usize = 0;
    let mut q: usize = 0;
    let mut pset: Sieve = Sieve::new();
    let mut rng: ThreadRng = rand::thread_rng();

    while p == q {
        p = (pset
            .iter()
            .enumerate()
            .skip(100)
            .choose(&mut rng)
            .unwrap()
            .1) as usize;
        q = (pset
            .iter()
            .enumerate()
            .skip(100)
            .choose(&mut rng)
            .unwrap()
            .1) as usize;
    }
    return PrimeBase { p, q };
}

pub fn generate_keys() -> (PublicKey, PrivateKey)
{
    let base = generate_base();
    let public_key = generate_public_key(&base);
    let private_key = generate_private_key(&public_key.0, public_key.1, base.q * base.p);
    return (public_key.0, private_key);
}