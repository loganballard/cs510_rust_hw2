use toy_rsa::rsa_library::{genkey, encrypt, decrypt};

fn main() {
    let msg: u32 = 12345;
//    for i in 0..100 {
//        let key_pair: (u32, u32) = genkey();
//        let pub_key = key_pair.0;
//        let pri_key = key_pair.1 as u64;
//        let x: u64 = encrypt(pri_key, msg);
//        let y: u32 = decrypt(key_pair, msg as u64);
//        println!("{}", y);
//    }
    let p: u32 = 0xed23e6cd;
    let q: u32 = 0xf050a04d;
    let pub_key: u64 = 0xde9c5816141c8ba9;
    let enc = encrypt(pub_key, msg);
    let dec = decrypt((p, q), enc);
    println!("enc: {}, dec: {}", enc, dec);
}
