// $ cargo run --release -- --number-of-outputs 1 --iv "" --key ""
pub mod aes128_bool_circ;
pub mod aes128_cipher;
pub mod aes128_keyschedule;
pub mod aes128_rdx_fhe;
pub mod aes128_tables;
pub mod aes_fhe;

pub use crate::aes_fhe::gen_rdx_keys;
pub use crate::aes128_cipher::{decrypt_block_iter_fhe, encrypt_block_iter_fhe};
pub use crate::aes128_keyschedule::{BLOCKSIZE, key_expansion};
pub use crate::aes128_rdx_fhe::encrypt_one_block_fhe;

use clap::{Arg, Command};

use std::fmt::Write;
use std::time::{Duration, Instant};

use aes::Aes128;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit, generic_array::GenericArray};

const IV: &str = "0123456789abcdef";
const KEY: &str = "000102030405060708090a0b0c0d0e0f";

fn cli() -> (u32, u32, String, String) {
    let matches = Command::new("CLI Parser AES")
        .version("1.0")
        .about("Parses command-line arguments")
        .arg(
            Arg::new("mode")
                .long("mode")
                .short('m')
                .help("Mode CTR or OFB")
                .default_value("1"),
        )
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

    let mode = matches
        .get_one::<String>("mode")
        .expect("Argument missing")
        .parse::<u32>()
        .expect("Invalid number for number-of-outputs");

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
    println!();

    assert!(iv.len() == 16);
    assert!(key.len() == 32);

    (mode, number_of_outputs, iv.clone(), key.clone())
}

// https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_(CTR)
fn main() {
    let (mode, no, iv_str, key_str) = cli();

    let mut key = [0u8; 16];
    let mut iv = [0u8; 16];

    for (i, chunk) in iv_str.as_bytes().chunks(2).enumerate() {
        iv[i] = u8::from_str_radix(&String::from_utf8_lossy(chunk), 16).expect("Invalid hex pair");
    }

    for (i, chunk) in key_str.as_bytes().chunks(2).enumerate() {
        key[i] = u8::from_str_radix(&String::from_utf8_lossy(chunk), 16).expect("Invalid hex pair");
    }

    if mode == 1 {
        let mut aes_out = [0u8; BLOCKSIZE];
        println!("generate_keys");
        let (ck, sk) = gen_rdx_keys();

        let mut elapsed = Duration::default();
        let start = Instant::now();
        let xk = key_expansion(&key);
        let key_expansion_elapsed = start.elapsed();

        let mut ctr = 0_u64;

        for i in 0..no {
            let bytes_be = ctr.to_be_bytes();
            ctr += 1;
            iv[8..].copy_from_slice(&bytes_be);
            let hex_str = iv.iter().fold(String::new(), |mut acc, b| {
                write!(&mut acc, "{:02x}", b).unwrap();
                acc
            });

            let mut ga_block = GenericArray::from(iv);
            let cipher = Aes128::new(&GenericArray::from(key));
            cipher.encrypt_block(&mut ga_block);
            let aes_ref: [u8; 16] = ga_block.into();

            let start = Instant::now();
            encrypt_one_block_fhe(&iv, &xk, &mut aes_out, &sk, &ck);
            let delta = start.elapsed();
            elapsed += delta;

            println!("Block {:}", (i + 1));
            println!("IV:                {}", hex_str);
            let hex_str = aes_ref.iter().fold(String::new(), |mut acc, b| {
                write!(&mut acc, "{:02x}", b).unwrap();
                acc
            });
            println!("AES ref:           {}", hex_str);
            let hex_str = aes_out.iter().fold(String::new(), |mut acc, b| {
                write!(&mut acc, "{:02x}", b).unwrap();
                acc
            });
            println!("AES cloud:         {}", hex_str);
            assert_eq!(aes_ref, aes_out);
            println!();
        }

        println!("AES key expansion took: {key_expansion_elapsed:?}");
        println!("AES of #{no} outputs computed in: {elapsed:?}");
    } else {
        let mut ga_block = GenericArray::from(iv);
        let cipher = Aes128::new(&GenericArray::from(key));

        for _ in 0..no {
            cipher.encrypt_block(&mut ga_block);
        }
        let out = encrypt_block_iter_fhe(&iv, &key, no as usize);

        println!("Ref AES-OFB        {:x}", ga_block);
        println!("enc                {:?} ", out);
        assert_eq!(ga_block, GenericArray::from(out));

        for _ in 0..no {
            cipher.decrypt_block(&mut ga_block);
        }
        let out = decrypt_block_iter_fhe(&out, &key, no as usize);

        println!("Ref AES-OFB        {:x}", ga_block);
        println!("dec                {:?}", out);
        assert_eq!(ga_block, GenericArray::from(out));
    }
}
