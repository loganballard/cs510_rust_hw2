#[cfg(test)]
mod tests {
    use crate::rsa_library::*;
    use rand::random;
    use toy_rsa_lib::gcd;

    #[test]
    fn test_encrypt() {
        assert_eq!(encrypt(18282, 32), 6500);
        assert_eq!(encrypt(55, 3), 53);
        assert_eq!(encrypt(0xde9c_5816_141c_8ba9, 12345), 0x164e_44b8_6776_d497);
    }

    #[test]
    fn test_decrypt() {
        let msg: u32 = 12345;
        let p: u32 = 0xed23e6cd;
        let q: u32 = 0xf050a04d;
        let pub_key: u64 = 0xde9c5816141c8ba9;
        let enc = encrypt(pub_key, msg);
        let dec = decrypt((p, q), enc);
        assert_eq!(msg, dec);
    }

    #[test]
    fn test_genkey() {
        for _ in 1..10 {
            let key = genkey();
            assert!(key.0 > 0);
            assert!(key.1 > 0);
            assert_eq!(gcd(key.0 as u64, EXP), 1);
            assert_eq!(gcd(key.1 as u64, EXP), 1);
            for i in 1..1000 {
                assert_eq!(gcd(key.0 as u64, i), 1);
                assert_eq!(gcd(key.1 as u64, i), 1);
            }
        }
    }

    #[test]
    fn test_workflow() {
        for _ in 1..100 {
            let msg: u32 = random();
            let key_tup = genkey();
            let p: u32 = key_tup.0;
            let q: u32 = key_tup.1;
            let pub_key: u64 = key_tup.0 as u64 * key_tup.1 as u64;
            let enc = encrypt(pub_key, msg);
            let dec = decrypt((p, q), enc);
            assert_eq!(msg, dec);
        }
    }
}

pub mod rsa_library {
    use std::convert::TryFrom;
    use toy_rsa_lib::*;

    /// Fixed RSA encryption exponent.
    pub const EXP: u64 = 65537;

    #[test]
    fn test_lambda() {
        assert_eq!(lambda(4, 5), 12);
        assert_eq!(lambda(10, 13), 36);
    }

    fn lambda(x: u64, y: u64) -> u64 {
        lcm(x - 1, y - 1)
    }

    /// Encrypt the plaintext `msg` using the RSA public `key`
    /// and return the ciphertext.
    pub fn encrypt(key: u64, msg: u32) -> u64 {
        let msg_64: u64 = msg as u64;
        modexp(msg_64, EXP, key)
    }

    /// Decrypt the cipertext `msg` using the RSA private `key`
    /// and return the resulting plaintext.
    pub fn decrypt(key: (u32, u32), msg: u64) -> u32 {
        let first_key_val: u64 = key.0 as u64;
        let sec_key_val: u64 = key.1 as u64;
        let pub_key: u64 = first_key_val * sec_key_val;
        let d: u64 = modinverse(EXP, lambda(first_key_val, sec_key_val));
        let decrypted = modexp(msg, d, pub_key);
        let decrypted_32 = u32::try_from(decrypted);
        match decrypted_32 {
            Ok(_) => (),
            Err(e) => panic!(
                "this was the problem when converting from u64 -> u32: {}",
                e
            ),
        }
        decrypted_32.unwrap()
    }

    /// Generate a pair of primes in the range `2**30..2**31`
    /// suitable for RSA encryption with exponent
    /// `EXP`. Warning: this routine has unbounded runtime; it
    /// works by generate-and-test, generating pairs of primes
    /// `p` `q` and testing that they satisfy `λ(pq) <= EXP` and
    /// that `λ(pq)` has no common factors with `EXP`.
    pub fn genkey() -> (u32, u32) {
        loop {
            let prime1: u32 = rsa_prime();
            let prime2: u32 = rsa_prime();
            let lambda_result = lambda(prime1 as u64, prime2 as u64);
            if (EXP < lambda_result) && (gcd(EXP, lambda_result) == 1) {
                return (prime1, prime2);
            }
        }
    }
}
