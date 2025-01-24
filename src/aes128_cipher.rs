use crate::aes128_keyschedule::{BLOCKSIZE, KEYSIZE, key_expansion};
use crate::aes128_rdx_fhe::{decrypt_block_fhe, encrypt_block_fhe};

use std::time::Instant;

pub fn encrypt_block_iter_fhe(
    input: &[u8; BLOCKSIZE],
    key: &[u8; KEYSIZE],
    iter: usize,
) -> [u8; BLOCKSIZE] {
    let mut out_iter = [0u8; BLOCKSIZE];

    let start = Instant::now();
    let xk = key_expansion(key);
    let key_expansion_elapsed = start.elapsed();
    println!("AES key expansion took: {key_expansion_elapsed:?}");

    encrypt_block_fhe(input, &xk, &mut out_iter, iter);
    println!("cipher encrypt {:?}", out_iter);

    out_iter
}

pub fn decrypt_block_iter_fhe(
    input: &[u8; BLOCKSIZE],
    key: &[u8; KEYSIZE],
    iter: usize,
) -> [u8; BLOCKSIZE] {
    let mut out_iter = [0u8; BLOCKSIZE];

    let start = Instant::now();
    let xk = key_expansion(key);
    let key_expansion_elapsed = start.elapsed();
    println!("AES key expansion took: {key_expansion_elapsed:?}");

    decrypt_block_fhe(input, &xk, &mut out_iter, iter);

    out_iter
}
