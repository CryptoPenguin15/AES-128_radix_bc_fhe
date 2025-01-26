use crate::aes_fhe::{NUM_BLOCK, dec_rdx_vec, enc_rdx_vec, gen_rdx_keys, print_hex_rdx_fhe};

use crate::aes128_bool_circ::{PosVals, sbox_idx, sbox_inv_idx};
use crate::aes128_keyschedule::{BLOCKSIZE, KEYSIZE, ROUNDKEYSIZE, ROUNDS};
use crate::aes128_tables::{GMUL2, GMUL3, GMUL9, GMULB, GMULD, GMULE, gen_tbl};

use tfhe::MatchValues;
use tfhe::integer::ServerKey;

use tfhe::integer::ciphertext::BaseRadixCiphertext;
use tfhe::shortint::Ciphertext;

use std::time::Instant;

use rayon::prelude::*;

#[inline]
fn add_round_key_fhe(
    state: &mut [BaseRadixCiphertext<Ciphertext>],
    rkey: &[BaseRadixCiphertext<Ciphertext>],
    sk: &ServerKey,
) {
    let start = Instant::now();

    state.par_iter_mut().enumerate().for_each(|(i, elem)| {
        let start = Instant::now();
        *elem = sk.unchecked_bitxor(elem, &rkey[i]);
        println!("unchecked_bitxor         {:.2?}", start.elapsed());
    });

    println!("add_round_key_fhe       {:.2?}", start.elapsed());
}

#[inline]
pub fn sub_bytes_fhe(
    state: &mut [BaseRadixCiphertext<Ciphertext>],
    pos_vals: &PosVals,
    sk: &ServerKey,
) {
    let start = Instant::now();
    let tmp = state.to_vec();

    state.par_iter_mut().enumerate().for_each(|(i, elem)| {
        *elem = sbox_idx(&tmp[i], pos_vals, sk);
    });

    println!("sub_bytes_fhe           {:.2?}", start.elapsed());
}

#[inline]
pub fn inv_sub_bytes_fhe(
    state: &mut [BaseRadixCiphertext<Ciphertext>],
    pos_vals: &PosVals,
    sk: &ServerKey,
) {
    let start = Instant::now();
    assert!(state.len() % 2 == 0);
    let tmp = state.to_vec();

    state.par_iter_mut().enumerate().for_each(|(i, elem)| {
        *elem = sbox_inv_idx(&tmp[i], pos_vals, sk);
    });

    println!("inv_sub_bytes_fhe   {:.2?}", start.elapsed());
}

#[inline]
fn shift_rows_fhe(state: &mut [BaseRadixCiphertext<Ciphertext>]) {
    let start = Instant::now();
    let tmp = state.to_vec();

    // col. 0
    state[0] = tmp[0].clone();
    state[1] = tmp[5].clone();
    state[2] = tmp[10].clone();
    state[3] = tmp[15].clone();

    // col. 1
    state[4] = tmp[4].clone();
    state[5] = tmp[9].clone();
    state[6] = tmp[14].clone();
    state[7] = tmp[3].clone();

    // col. 2
    state[8] = tmp[8].clone();
    state[9] = tmp[13].clone();
    state[10] = tmp[2].clone();
    state[11] = tmp[7].clone();

    // col. 3
    state[12] = tmp[12].clone();
    state[13] = tmp[1].clone();
    state[14] = tmp[6].clone();
    state[15] = tmp[11].clone();

    println!("shift_rows_fhe          {:.2?}", start.elapsed());
}

#[inline]
fn inv_shift_rows_fhe(state: &mut [BaseRadixCiphertext<Ciphertext>]) {
    let start = Instant::now();
    let tmp = state.to_vec();

    // col. 0
    state[0] = tmp[0].clone();
    state[1] = tmp[13].clone();
    state[2] = tmp[10].clone();
    state[3] = tmp[7].clone();

    // col. 1
    state[4] = tmp[4].clone();
    state[5] = tmp[1].clone();
    state[6] = tmp[14].clone();
    state[7] = tmp[11].clone();

    // col. 2
    state[8] = tmp[8].clone();
    state[9] = tmp[5].clone();
    state[10] = tmp[2].clone();
    state[11] = tmp[15].clone();

    // col. 3
    state[12] = tmp[12].clone();
    state[13] = tmp[9].clone();
    state[14] = tmp[6].clone();
    state[15] = tmp[3].clone();

    println!("inv_shift_rows_fhe      {:.2?}", start.elapsed());
}

#[inline]
fn lut_state(
    state: &mut [BaseRadixCiphertext<Ciphertext>],
    tbl: &MatchValues<u8>,
    sk: &ServerKey,
) -> [BaseRadixCiphertext<Ciphertext>; 16] {
    let start = Instant::now();
    assert!(state.len() == 16);

    let mut tmp = state.to_vec();
    tmp.par_iter_mut().enumerate().for_each(|(i, elem)| {
        (*elem, _) = sk.unchecked_match_value_parallelized(&state[i], tbl);
    });

    println!("m_col lut time         {:.2?}", start.elapsed());
    let tmp: [BaseRadixCiphertext<Ciphertext>; 16] =
        tmp.try_into().expect("Expected a Vec of length 16");

    tmp
}

#[inline]
fn parallel_xor(
    g1_g2_xor: &mut [BaseRadixCiphertext<Ciphertext>],
    g1_state: &[BaseRadixCiphertext<Ciphertext>],
    g2_state: &[BaseRadixCiphertext<Ciphertext>],
    idx1: &[usize],
    idx2: &[usize],
    sk: &ServerKey,
) {
    let start = Instant::now();
    assert!(idx1.len() == 4);
    assert!(idx2.len() == 4);

    g1_g2_xor
        .par_iter_mut()
        .with_max_len(1)
        .enumerate()
        .for_each(|(i, elem)| {
            let mut c: usize = i / 4; // 0..=3 => 0, 4..=7 => 1, 8..=11 => 2, 12..=15 => 3
            c *= 4;

            let p: usize = i % 4;
            *elem = sk.unchecked_bitxor(&g1_state[c + idx1[p]], &g2_state[c + idx2[p]]);
        });

    println!("m_col gx xor gy time    {:.2?}", start.elapsed());
}

#[inline]
fn mix_columns_fhe(
    state: &mut [BaseRadixCiphertext<Ciphertext>],
    gmul2_tbl: &MatchValues<u8>,
    gmul3_tbl: &MatchValues<u8>,
    sk: &ServerKey,
) {
    let start = Instant::now();
    assert!(state.len() == 16);

    let g2_state = lut_state(state, gmul2_tbl, sk);
    let g3_state = lut_state(state, gmul3_tbl, sk);

    let mut binding: Vec<BaseRadixCiphertext<Ciphertext>> = (0..16)
        .map(|_| sk.create_trivial_radix(0, NUM_BLOCK))
        .collect();
    let g2_g3_xor = binding.as_mut_slice();
    let g2_idx = vec![0, 1, 2, 3];
    let g3_idx = vec![1, 2, 3, 0];
    parallel_xor(g2_g3_xor, &g2_state, &g3_state, &g2_idx, &g3_idx, sk);

    let mut binding: Vec<BaseRadixCiphertext<Ciphertext>> = (0..16)
        .map(|_| sk.create_trivial_radix(0, NUM_BLOCK))
        .collect();
    let s1_s2_xor = binding.as_mut_slice();
    let s1_idx = vec![2, 0, 0, 1];
    let s2_idx = vec![3, 3, 1, 2];
    parallel_xor(s1_s2_xor, state, state, &s1_idx, &s2_idx, sk);

    state
        .par_iter_mut()
        .enumerate()
        .for_each(|(i, state_elem)| {
            *state_elem = sk.unchecked_bitxor(&g2_g3_xor[i], &s1_s2_xor[i]);
        });

    println!("m_col time              {:.2?}", start.elapsed());
}

#[inline]
fn inv_mix_columns_fhe(
    state: &mut [BaseRadixCiphertext<Ciphertext>],
    gmul9_tbl: &MatchValues<u8>,
    gmulb_tbl: &MatchValues<u8>,
    gmuld_tbl: &MatchValues<u8>,
    gmule_tbl: &MatchValues<u8>,
    sk: &ServerKey,
) {
    let start = Instant::now();
    assert!(state.len() == 16);

    let g9_state = lut_state(state, gmul9_tbl, sk);
    let gb_state = lut_state(state, gmulb_tbl, sk);
    let gd_state = lut_state(state, gmuld_tbl, sk);
    let ge_state = lut_state(state, gmule_tbl, sk);

    let mut binding: Vec<BaseRadixCiphertext<Ciphertext>> = (0..16)
        .map(|_| sk.create_trivial_radix(0, NUM_BLOCK))
        .collect();
    let g9_gb_xor = binding.as_mut_slice();
    let g9_idx = vec![3, 0, 1, 2];
    let gb_idx = vec![1, 2, 3, 0];
    parallel_xor(g9_gb_xor, &g9_state, &gb_state, &g9_idx, &gb_idx, sk);

    let mut binding: Vec<BaseRadixCiphertext<Ciphertext>> = (0..16)
        .map(|_| sk.create_trivial_radix(0, NUM_BLOCK))
        .collect();
    let gd_ge_xor = binding.as_mut_slice();
    let gd_idx = vec![2, 3, 0, 1];
    let ge_idx = vec![0, 1, 2, 3];
    parallel_xor(gd_ge_xor, &gd_state, &ge_state, &gd_idx, &ge_idx, sk);

    state
        .par_iter_mut()
        .enumerate()
        .for_each(|(i, state_elem)| {
            *state_elem = sk.unchecked_bitxor(&g9_gb_xor[i], &gd_ge_xor[i]);
        });

    println!("inv_mix_columns_fhe time {:.2?}", start.elapsed());
}

pub fn encrypt_block_fhe(
    input: &[u8; KEYSIZE],
    xk: &[u8; ROUNDKEYSIZE],
    output: &mut [u8; BLOCKSIZE],
    iter: usize,
) {
    let mut state = [0u8; BLOCKSIZE];
    state.copy_from_slice(input);

    println!("generate_keys");
    let (ck, sk) = gen_rdx_keys();
    let pos_vals = PosVals::new(&ck);

    let mut state_ck = enc_rdx_vec(&state, &ck);
    let xk_ck = enc_rdx_vec(xk, &ck);

    println!("generate_match_value_tables");
    let gmul2_tbl = gen_tbl(&GMUL2);
    let gmul3_tbl = gen_tbl(&GMUL3);

    let tot = Instant::now();
    for i in 1..=iter {
        println!("Encrypting iteration: {}", i);

        let start = Instant::now();

        print_hex_rdx_fhe("input", 0, &state_ck, &ck);
        add_round_key_fhe(&mut state_ck, &xk_ck[..2 * BLOCKSIZE], &sk);
        print_hex_rdx_fhe("k_sch", 0, &state_ck, &ck);

        for round in 1..ROUNDS {
            sub_bytes_fhe(&mut state_ck, &pos_vals, &sk);
            print_hex_rdx_fhe("s_box", round, &state_ck, &ck);

            shift_rows_fhe(&mut state_ck);
            print_hex_rdx_fhe("s_row", round, &state_ck, &ck);

            mix_columns_fhe(&mut state_ck, &gmul2_tbl, &gmul3_tbl, &sk);
            print_hex_rdx_fhe("m_col", round, &state_ck, &ck);

            add_round_key_fhe(&mut state_ck, &xk_ck[round * KEYSIZE..ROUNDKEYSIZE], &sk);
            print_hex_rdx_fhe("k_sch", round, &state_ck, &ck);
        }

        sub_bytes_fhe(&mut state_ck, &pos_vals, &sk);
        print_hex_rdx_fhe("s_box", 10, &state_ck, &ck);

        shift_rows_fhe(&mut state_ck);
        print_hex_rdx_fhe("s_row", 10, &state_ck, &ck);

        add_round_key_fhe(&mut state_ck, &xk_ck[KEYSIZE * ROUNDS..ROUNDKEYSIZE], &sk);
        print_hex_rdx_fhe("k_sch", 10, &state_ck, &ck);

        println!("encrypt_block_fhe         {:.2?}", start.elapsed());
    }
    let elapsed = tot.elapsed();
    println!("AES of #{iter} outputs computed in: {elapsed:?}");

    let output_vec = dec_rdx_vec(&state_ck, &ck);
    output.copy_from_slice(&output_vec);
    println!("outpt_vec {:?}", output_vec);
    println!("outpt     {:?}", output);
}

pub fn decrypt_block_fhe(
    input: &[u8; BLOCKSIZE],
    xk: &[u8; ROUNDKEYSIZE],
    output: &mut [u8; BLOCKSIZE],
    iter: usize,
) {
    let mut state = [0u8; BLOCKSIZE];
    state.copy_from_slice(input);

    println!("generate_keys");
    let (ck, sk) = gen_rdx_keys();
    let pos_vals = PosVals::new(&ck);

    let mut state_ck = enc_rdx_vec(&state, &ck);
    let xk_ck = enc_rdx_vec(xk, &ck);

    println!("generate_match_value_tables");
    let gmul9_tbl = gen_tbl(&GMUL9);
    let gmulb_tbl = gen_tbl(&GMULB);
    let gmuld_tbl = gen_tbl(&GMULD);
    let gmule_tbl = gen_tbl(&GMULE);

    let tot = Instant::now();
    for i in 1..=iter {
        println!("Decrypting iteration: {}", i);

        let start = Instant::now();

        print_hex_rdx_fhe("iinput", 0, &state_ck, &ck);
        add_round_key_fhe(&mut state_ck, &xk_ck[KEYSIZE * ROUNDS..ROUNDKEYSIZE], &sk);
        print_hex_rdx_fhe("ik_sch", 0, &state_ck, &ck);

        for round in (1..ROUNDS).rev() {
            inv_shift_rows_fhe(&mut state_ck);
            print_hex_rdx_fhe("is_row", round, &state_ck, &ck);

            inv_sub_bytes_fhe(&mut state_ck, &pos_vals, &sk);
            print_hex_rdx_fhe("is_box", round, &state_ck, &ck);

            add_round_key_fhe(
                &mut state_ck,
                &xk_ck[round * KEYSIZE..(round + 1) * KEYSIZE],
                &sk,
            );
            print_hex_rdx_fhe("ik_sch", round, &state_ck, &ck);

            inv_mix_columns_fhe(
                &mut state_ck,
                &gmul9_tbl,
                &gmulb_tbl,
                &gmuld_tbl,
                &gmule_tbl,
                &sk,
            );
            print_hex_rdx_fhe("ik_add", round, &state_ck, &ck);
        }

        inv_shift_rows_fhe(&mut state_ck);
        print_hex_rdx_fhe("is_row", 0, &state_ck, &ck);

        inv_sub_bytes_fhe(&mut state_ck, &pos_vals, &sk);
        print_hex_rdx_fhe("is_box", 0, &state_ck, &ck);

        add_round_key_fhe(&mut state_ck, &xk_ck[..2 * BLOCKSIZE], &sk);
        print_hex_rdx_fhe("ik_sch", 0, &state_ck, &ck);

        println!("decrypt_block_fhe         {:.2?}", start.elapsed());
    }
    let elapsed = tot.elapsed();
    println!("AES of #{iter} outputs computed in: {elapsed:?}");

    let output_vec = dec_rdx_vec(&state_ck, &ck);
    output.copy_from_slice(&output_vec);
}
