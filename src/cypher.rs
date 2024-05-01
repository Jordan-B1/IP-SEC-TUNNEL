pub fn enigma(data: &Vec<u8>, exponent: usize, modulus: usize) -> Vec<u8> {
    data.iter().map(|&byte| ((byte as usize ^ exponent) % modulus) as u8).collect()
}
