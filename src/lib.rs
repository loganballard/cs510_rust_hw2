use toy_rsa_lib::*;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}

//
///// Generate a pair of primes in the range `2**30..2**31`
///// suitable for RSA encryption with exponent
///// `EXP`. Warning: this routine has unbounded runtime; it
///// works by generate-and-test, generating pairs of primes
///// `p` `q` and testing that they satisfy `λ(pq) <= EXP` and
///// that `λ(pq)` has no common factors with `EXP`.
//pub fn genkey() -> (u32, u32) {}
//
//
///// Decrypt the cipertext `msg` using the RSA private `key`
///// and return the resulting plaintext.
//pub fn decrypt(key: (u32, u32), msg: u64) -> u32 {}

#[test]
fn test_lambda() {
    assert_eq!(lambda(4, 5), 12);
    assert_eq!(lambda(10, 13), 36);
}

fn lambda(x: u64, y: u64) -> u64 {
    lcm(x - 1, y - 1)
}

/// Fixed RSA encryption exponent.
pub const EXP: u64 = 65537;

#[test]
fn test_encrypt() {
    assert_eq!(encrypt(18282, 32), 6500);
    assert_eq!(encrypt(55, 3), 53);
}

/// Encrypt the plaintext `msg` using the RSA public `key`
/// and return the ciphertext.
pub fn encrypt(key: u64, msg: u32) -> u64 {
    let msg_64 : u64 = msg as u64;
    modexp(msg_64, EXP, key)
}