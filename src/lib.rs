#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}

pub mod rsa_library {
    use toy_rsa_lib::*;

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
        let msg_64: u64 = msg as u64;
        modexp(msg_64, EXP, key)
    }

    //#[test]
    //fn test_decrypt() {
    //    let key: u64 = 11111;
    //    let msg: u32 = 12345;
    //    let enc_val: u64 = encrypt(pub_key, msg);
    //    let dec_val: u32 = decrypt(pri_key, msg);
    //}

    /// Decrypt the cipertext `msg` using the RSA private `key`
    /// and return the resulting plaintext.
    pub fn decrypt(key: (u32, u32), msg: u64) -> u32 {
        let first_key_val: u64 = key.0 as u64;
        let sec_key_val: u64 = key.1 as u64;
        let d: u64 = modinverse(lambda(first_key_val, sec_key_val), EXP);
        modexp(msg, d, first_key_val * sec_key_val) as u32
    }

//    #[test]
//    fn test_genkey() {
//        let key = genkey();
//        assert_eq!(1, 1);
//    }


    /// Generate a pair of primes in the range `2**30..2**31`
    /// suitable for RSA encryption with exponent
    /// `EXP`. Warning: this routine has unbounded runtime; it
    /// works by generate-and-test, generating pairs of primes
    /// `p` `q` and testing that they satisfy `λ(pq) <= EXP` and
    /// that `λ(pq)` has no common factors with `EXP`.
    pub fn genkey() -> (u32, u32) {
        // TODO - need to fix scoping issues with the while loop here
        let mut key_pair: (u32, u32) = (2, 2);
        let mut key_pair_64: (u64, u64) = (2, 2);
        let mut lambda_result = lambda(key_pair_64.0, key_pair_64.1);
        while (EXP >= lambda_result) && (gcd(EXP, lambda_result) != 1) {
            key_pair.0 = rsa_prime();
            key_pair.1 = rsa_prime();
            key_pair_64.0 = key_pair.0 as u64;
            key_pair_64.1 = key_pair.1 as u64;
            lambda_result = lambda(key_pair_64.0, key_pair_64.1);
        }
        key_pair
    }
}