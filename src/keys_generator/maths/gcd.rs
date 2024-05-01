pub fn compute_gcd(a: usize, b: usize) -> usize
{
    let greatest: usize = std::cmp::max(a, b);
    let lowest: usize = std::cmp::min(a, b);
    let left: usize = greatest % lowest;

    if greatest % lowest == 0 {
        return lowest;
    }
    return compute_gcd(lowest, left);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gcd() {
        assert_eq!(compute_gcd(100, 9), 1);
        assert_eq!(compute_gcd(9, 100), 1);
        assert_eq!(compute_gcd(90, 100), 10);
        assert_eq!(compute_gcd(559, 255), 1);
    }
}