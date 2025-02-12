pub use aes128_rdx_bc_fhe::aes_fhe::{enc_rdx_vec, gen_rdx_keys, print_hex_rdx_fhe};
pub use aes128_rdx_bc_fhe::aes128_bool_circ::{PosVals, mix_cols, sbox_idx, sbox_inv_idx};
pub use aes128_rdx_bc_fhe::aes128_keyschedule::key_expansion;
pub use aes128_rdx_bc_fhe::aes128_rdx_fhe::{decrypt_block_fhe, encrypt_block_fhe, sub_bytes_fhe};
pub use aes128_rdx_bc_fhe::aes128_tables::{GMUL2, GMUL3, SBOX, gen_tbl};

use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;

use tfhe::integer::ciphertext::BaseRadixCiphertext;
use tfhe::integer::gen_keys_radix;
use tfhe::shortint::Ciphertext;

use aes::Aes128;
use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};

use rand::RngCore;
use rand::rngs::OsRng;
use std::time::Instant;

pub struct KeyTest {
    pub key: &'static [u8],
    pub enc: &'static [u8],
}

pub const KEY_TESTS: &[KeyTest] = &[KeyTest {
    key: &[
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ],
    enc: &[
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0xd6, 0xaa, 0x74, 0xfd, 0xd2, 0xaf, 0x72, 0xfa, 0xda, 0xa6, 0x78, 0xf1, 0xd6, 0xab,
        0x76, 0xfe, 0xb6, 0x92, 0xcf, 0x0b, 0x64, 0x3d, 0xbd, 0xf1, 0xbe, 0x9b, 0xc5, 0x00, 0x68,
        0x30, 0xb3, 0xfe, 0xb6, 0xff, 0x74, 0x4e, 0xd2, 0xc2, 0xc9, 0xbf, 0x6c, 0x59, 0x0c, 0xbf,
        0x04, 0x69, 0xbf, 0x41, 0x47, 0xf7, 0xf7, 0xbc, 0x95, 0x35, 0x3e, 0x03, 0xf9, 0x6c, 0x32,
        0xbc, 0xfd, 0x05, 0x8d, 0xfd, 0x3c, 0xaa, 0xa3, 0xe8, 0xa9, 0x9f, 0x9d, 0xeb, 0x50, 0xf3,
        0xaf, 0x57, 0xad, 0xf6, 0x22, 0xaa, 0x5e, 0x39, 0x0f, 0x7d, 0xf7, 0xa6, 0x92, 0x96, 0xa7,
        0x55, 0x3d, 0xc1, 0x0a, 0xa3, 0x1f, 0x6b, 0x14, 0xf9, 0x70, 0x1a, 0xe3, 0x5f, 0xe2, 0x8c,
        0x44, 0x0a, 0xdf, 0x4d, 0x4e, 0xa9, 0xc0, 0x26, 0x47, 0x43, 0x87, 0x35, 0xa4, 0x1c, 0x65,
        0xb9, 0xe0, 0x16, 0xba, 0xf4, 0xae, 0xbf, 0x7a, 0xd2, 0x54, 0x99, 0x32, 0xd1, 0xf0, 0x85,
        0x57, 0x68, 0x10, 0x93, 0xed, 0x9c, 0xbe, 0x2c, 0x97, 0x4e, 0x13, 0x11, 0x1d, 0x7f, 0xe3,
        0x94, 0x4a, 0x17, 0xf3, 0x07, 0xa7, 0x8b, 0x4d, 0x2b, 0x30, 0xc5,
    ],
}];

const SBOX_INV: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
];

#[cfg(test)]
mod tests {
    use aes128_rdx_bc_fhe::aes_fhe::NUM_BLOCK;

    use super::*;

    #[test]
    fn test_key_expansion() {
        for (i, test) in KEY_TESTS.iter().enumerate() {
            let key: &[u8; 16] = test
                .key
                .try_into()
                .expect("Key must be 128 bits (16 bytes)");
            let xk = key_expansion(key);

            for (j, &v) in xk.iter().enumerate() {
                assert_eq!(
                    v, test.enc[j],
                    "key {}: enc[{}] = {:#x}, want {:#x}",
                    i, j, v, test.enc[j]
                );
            }
        }
    }

    #[test]
    fn test_encrypt_block_tfhe1() {
        let plaintext: [u8; 16] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let key: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let expected_ciphertext: [u8; 16] = [
            0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4,
            0xc5, 0x5a,
        ];

        let xk = key_expansion(&key);

        let mut dst = [0u8; 16];
        encrypt_block_fhe(&plaintext, &xk, &mut dst, 1);

        assert_eq!(
            dst, expected_ciphertext,
            "Encryption failed\nExpected: {:x?}\nGot: {:x?}",
            expected_ciphertext, dst
        );
    }

    #[test]
    fn test_decrypt_block_tfhe1() {
        let ciphertext: [u8; 16] = [
            0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4,
            0xc5, 0x5a,
        ];
        let key: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let expected_plaintext: [u8; 16] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];

        let xk = key_expansion(&key);

        let mut dst = [0u8; 16];
        decrypt_block_fhe(&ciphertext, &xk, &mut dst, 1);

        assert_eq!(
            dst, expected_plaintext,
            "Encryption failed\nExpected: {:x?}\nGot: {:x?}",
            expected_plaintext, dst
        );
    }

    #[test]
    fn test_encrypt_block_tfhe2() {
        let plaintext: [u8; 16] = [
            0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93,
            0x17, 0x2A,
        ];
        let key: [u8; 16] = [
            0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF,
            0x4F, 0x3C,
        ];
        let expected_ciphertext: [u8; 16] = [
            0x3A, 0xD7, 0x7B, 0xB4, 0x0D, 0x7A, 0x36, 0x60, 0xA8, 0x9E, 0xCA, 0xF3, 0x24, 0x66,
            0xEF, 0x97,
        ];

        let xk = key_expansion(&key);

        let mut dst = [0u8; 16];
        encrypt_block_fhe(&plaintext, &xk, &mut dst, 1);

        assert_eq!(
            dst, expected_ciphertext,
            "Encryption failed\nExpected: {:x?}\nGot: {:x?}",
            expected_ciphertext, dst
        );
    }

    #[test]
    fn test_decrypt_block_tfhe2() {
        let ciphertext: [u8; 16] = [
            0x3A, 0xD7, 0x7B, 0xB4, 0x0D, 0x7A, 0x36, 0x60, 0xA8, 0x9E, 0xCA, 0xF3, 0x24, 0x66,
            0xEF, 0x97,
        ];
        let key: [u8; 16] = [
            0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF,
            0x4F, 0x3C,
        ];
        let expected_plaintext: [u8; 16] = [
            0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93,
            0x17, 0x2A,
        ];

        let xk = key_expansion(&key);

        let mut dst = [0u8; 16];
        decrypt_block_fhe(&ciphertext, &xk, &mut dst, 1);

        assert_eq!(
            dst, expected_plaintext,
            "Encryption failed\nExpected: {:x?}\nGot: {:x?}",
            expected_plaintext, dst
        );
    }

    #[test]
    fn test_encrypt_decrypt_rnd_block() {
        let mut key = [0u8; 16];
        OsRng.fill_bytes(&mut key);

        let mut iv = [0u8; 16];
        OsRng.fill_bytes(&mut iv);

        let mut expected = GenericArray::from(iv);
        let cipher = Aes128::new(&GenericArray::from(key));
        cipher.encrypt_block(&mut expected);

        let xk = key_expansion(&key);
        let mut dst = [0u8; 16];
        encrypt_block_fhe(&iv, &xk, &mut dst, 1);

        assert_eq!(
            GenericArray::from(dst),
            expected,
            "Encryption failed\nExpected: {:x?}\nGot: {:x?}",
            expected,
            dst
        );

        let mut out = [0u8; 16];
        decrypt_block_fhe(&dst, &xk, &mut out, 1);

        assert_eq!(
            out, iv,
            "Encryption failed\nExpected: {:x?}\nGot: {:x?}",
            expected, out
        );
    }

    #[test]
    fn test_perf_rdx_xor() {
        let (ck, sk) = gen_rdx_keys();

        let state = vec![0xfe, 0xff]; // byte to rdx
        let mut state_ck = enc_rdx_vec(&state, &ck);
        print_hex_rdx_fhe("state_ck      ", 0, &state_ck, &ck);

        let start = Instant::now();
        for _ in 1..10 {
            let tmp = state_ck.to_vec();
            state_ck[1] = sk.unchecked_bitxor(&tmp[0], &tmp[1]);
            state_ck[0] = sk.unchecked_bitxor(&tmp[1], &tmp[0]);
            print_hex_rdx_fhe("rdx bitxor", 0, &state_ck, &ck);
        }
        println!(
            "test_perf_rdx_xor {:.?}",
            start.elapsed().checked_div(2 * 10)
        );

        print_hex_rdx_fhe("rdx bitxor", 0, &state_ck, &ck);
    }

    // https://github.com/zama-ai/tfhe-rs/issues/816
    // https://doc.rust-lang.org/stable/std/array/fn.from_fn.html
    #[test]
    fn test_init_arr_ciphertext() {
        let (ck, sk) = gen_rdx_keys();

        let start = Instant::now();
        let state_ck: [BaseRadixCiphertext<Ciphertext>; 16] =
            core::array::from_fn(|_| sk.create_trivial_radix(0, NUM_BLOCK));
        println!("test_init_arr_ciphertext  {:.?}", start.elapsed());
        assert!(state_ck.len() == 16);

        print_hex_rdx_fhe("init arr ciphertext", 0, &state_ck.to_vec(), &ck);
    }

    #[test]
    fn test_init_vec_ciphertext() {
        let (ck, sk) = gen_rdx_keys();

        let start = Instant::now();
        let state_ck: Vec<BaseRadixCiphertext<Ciphertext>> = (0..16)
            .map(|_| sk.create_trivial_radix(0, NUM_BLOCK))
            .collect();

        println!("test_init_vec_ciphertext  {:.?}", start.elapsed());
        assert!(state_ck.len() == 16);

        print_hex_rdx_fhe("init vec ciphertext", 0, &state_ck, &ck);
    }

    #[test]
    fn test_sbox() {
        let (ck, sk) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, NUM_BLOCK);
        let pos_vals = PosVals::new(&ck);

        for i in 0..255 {
            let idx = ck.encrypt(i as u8);

            let sbox = sbox_idx(&idx, &pos_vals, &sk);
            let sbox_val = ck.decrypt::<u8>(&sbox);

            println!("i {:},  result {:x}", i, sbox_val);
            assert!(sbox_val == SBOX[i]);
        }
    }

    #[test]
    fn test_sbox_inv() {
        let (ck, sk) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, NUM_BLOCK);
        let pos_vals = PosVals::new(&ck);

        for i in 0..255 {
            let idx = ck.encrypt(i as u8);

            let sbox = sbox_inv_idx(&idx, &pos_vals, &sk);
            let sbox_val = ck.decrypt::<u8>(&sbox);

            println!("i {:},  result {:x}", i, sbox_val);
            assert!(sbox_val == SBOX_INV[i]);
        }
    }

    #[test]
    fn test_mix_cols_1() {
        let (ck, sk) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, NUM_BLOCK);
        let pos_vals = PosVals::new(&ck);

        let c1_pre = [0x01, 0x01, 0x01, 0x01];
        let c1_pst = [0x01, 0x01, 0x01, 0x01];

        let col = [
            ck.encrypt(c1_pre[0] as u8),
            ck.encrypt(c1_pre[1] as u8),
            ck.encrypt(c1_pre[2] as u8),
            ck.encrypt(c1_pre[3] as u8),
        ];

        let out = mix_cols(&col, &pos_vals, &sk);

        let dec = [
            ck.decrypt::<u8>(&out[0]),
            ck.decrypt::<u8>(&out[1]),
            ck.decrypt::<u8>(&out[2]),
            ck.decrypt::<u8>(&out[3]),
        ];

        for (i, (&pre, &post)) in c1_pre.iter().zip(dec.iter()).enumerate() {
            println!("r{}_in {:x}, r{}_out {:x}", i + 1, pre, i + 1, post);
            assert_eq!(post, c1_pst[i]);
        }
    }

    #[test]
    fn test_mix_cols_2() {
        let (ck, sk) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, NUM_BLOCK);
        let pos_vals = PosVals::new(&ck);

        let c1_pre = [0xc6, 0xc6, 0xc6, 0xc6];
        let c1_pst = [0xc6, 0xc6, 0xc6, 0xc6];

        let col = [
            ck.encrypt(c1_pre[0] as u8),
            ck.encrypt(c1_pre[1] as u8),
            ck.encrypt(c1_pre[2] as u8),
            ck.encrypt(c1_pre[3] as u8),
        ];

        let out = mix_cols(&col, &pos_vals, &sk);

        let dec = [
            ck.decrypt::<u8>(&out[0]),
            ck.decrypt::<u8>(&out[1]),
            ck.decrypt::<u8>(&out[2]),
            ck.decrypt::<u8>(&out[3]),
        ];

        for (i, (&pre, &post)) in c1_pre.iter().zip(dec.iter()).enumerate() {
            println!("r{}_in {:x}, r{}_out {:x}", i + 1, pre, i + 1, post);
            assert_eq!(post, c1_pst[i]);
        }
    }

    #[test]
    fn test_mix_cols_3() {
        let (ck, sk) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, NUM_BLOCK);
        let pos_vals = PosVals::new(&ck);

        let c1_pre = [0xd4, 0xbf, 0x5d, 0x30];
        let c1_pst = [0x04, 0x66, 0x81, 0xe5];

        let col = [
            ck.encrypt(c1_pre[0] as u8),
            ck.encrypt(c1_pre[1] as u8),
            ck.encrypt(c1_pre[2] as u8),
            ck.encrypt(c1_pre[3] as u8),
        ];

        let out = mix_cols(&col, &pos_vals, &sk);

        let dec = [
            ck.decrypt::<u8>(&out[0]),
            ck.decrypt::<u8>(&out[1]),
            ck.decrypt::<u8>(&out[2]),
            ck.decrypt::<u8>(&out[3]),
        ];

        for (i, (&pre, &post)) in c1_pre.iter().zip(dec.iter()).enumerate() {
            println!("r{}_in {:x}, r{}_out {:x}", i + 1, pre, i + 1, post);
            assert_eq!(post, c1_pst[i]);
        }
    }

    #[test]
    fn test_mix_cols_4() {
        let (ck, sk) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, NUM_BLOCK);
        let pos_vals = PosVals::new(&ck);

        let c1_pre = [0xe0, 0xb4, 0x52, 0xae];
        let c1_pst = [0xe0, 0xcb, 0x19, 0x9a];

        let col = [
            ck.encrypt(c1_pre[0] as u8),
            ck.encrypt(c1_pre[1] as u8),
            ck.encrypt(c1_pre[2] as u8),
            ck.encrypt(c1_pre[3] as u8),
        ];

        let out = mix_cols(&col, &pos_vals, &sk);

        let dec = [
            ck.decrypt::<u8>(&out[0]),
            ck.decrypt::<u8>(&out[1]),
            ck.decrypt::<u8>(&out[2]),
            ck.decrypt::<u8>(&out[3]),
        ];

        for (i, (&pre, &post)) in c1_pre.iter().zip(dec.iter()).enumerate() {
            println!("r{}_in {:x}, r{}_out {:x}", i + 1, pre, i + 1, post);
            assert_eq!(post, c1_pst[i]);
        }
    }
}
