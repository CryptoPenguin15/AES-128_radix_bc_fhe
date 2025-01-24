// $ cargo run --release -- --number-of-outputs 1 --iv "" --key ""
pub mod aes128_bool_circ;
pub mod aes128_cipher;
pub mod aes128_keyschedule;
pub mod aes128_rdx_fhe;
pub mod aes128_tables;
pub mod aes_fhe;

pub use crate::aes128_cipher::{decrypt_block_iter_fhe, encrypt_block_iter_fhe};
pub use crate::aes128_keyschedule::key_expansion;

use clap::{Arg, Command};

use aes::Aes128;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit, generic_array::GenericArray};

const IV: &str = "00112233445566778899aabbccddeeff";
const KEY: &str = "000102030405060708090a0b0c0d0e0f";

fn cli() -> (u32, String, String) {
    let matches = Command::new("CLI Parser AES-OFB")
        .version("1.0")
        .about("Parses command-line arguments")
        .arg(
            Arg::new("number_of_outputs")
                .long("number-of-outputs")
                .short('n')
                .help("Sets the number of blocks")
                .default_value("1"),
        )
        .arg(
            Arg::new("iv")
                .long("initialization-vector")
                .short('i')
                .help("Initialization vector")
                .default_value(IV),
        )
        .arg(
            Arg::new("key")
                .long("key")
                .short('k')
                .help("Key value")
                .default_value(KEY),
        )
        .get_matches();

    let number_of_outputs = matches
        .get_one::<String>("number_of_outputs")
        .expect("Argument missing")
        .parse::<u32>()
        .expect("Invalid number for number-of-outputs");
    let iv = matches.get_one::<String>("iv").expect("Argument missing");
    let key = matches.get_one::<String>("key").expect("Argument missing");

    println!("Number of outputs: {}", number_of_outputs);
    println!("IV:                {}", iv);
    println!("Key:               {}", key);

    assert!(iv.len() == 32);
    assert!(key.len() == 32);

    (number_of_outputs, iv.clone(), key.clone())
}

fn main() {
    let (no, iv_str, key_str) = cli();

    let mut key = [0u8; 16];
    let mut iv = [0u8; 16];

    for (i, chunk) in iv_str.as_bytes().chunks(2).enumerate() {
        iv[i] = u8::from_str_radix(&String::from_utf8_lossy(chunk), 16).expect("Invalid hex pair");
    }

    for (i, chunk) in key_str.as_bytes().chunks(2).enumerate() {
        key[i] = u8::from_str_radix(&String::from_utf8_lossy(chunk), 16).expect("Invalid hex pair");
    }

    let mut ga_block = GenericArray::from(iv);
    let cipher = Aes128::new(&GenericArray::from(key));

    for _ in 0..no {
        cipher.encrypt_block(&mut ga_block);
    }
    let out = encrypt_block_iter_fhe(&iv, &key, no as usize);

    println!("Ref AES-OFB        {:x}", ga_block);
    println!("enc                {:?} ", out);
    //assert_eq!(ga_block, GenericArray::from(out));

    for _ in 0..no {
        cipher.decrypt_block(&mut ga_block);
    }
    let out = decrypt_block_iter_fhe(&out, &key, no as usize);

    println!("Ref AES-OFB        {:x}", ga_block);
    println!("dec                {:?}", out);
    assert_eq!(ga_block, GenericArray::from(out));
}
