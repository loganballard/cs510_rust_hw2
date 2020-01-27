use toy_rsa::{decrypt, encrypt};

fn main() {
    let msg: u32 = 12345;
    let p: u32 = 0xed23_e6cd;
    let q: u32 = 0xf050_a04d;
    let pub_key: u64 = 0xde9c_5816_141c_8ba9;
    let enc = encrypt(pub_key, msg);
    let dec = decrypt((p, q), enc);
    println!("p: {}; q: {}; pubkey: {}", p, q, pub_key);
    println!("enc: {}, dec: {}", enc, dec);
}
