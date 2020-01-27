use rand::random;
use toy_rsa::*;
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
