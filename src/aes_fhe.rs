use tfhe::integer::ciphertext::BaseRadixCiphertext;
use tfhe::integer::{RadixClientKey, ServerKey, gen_keys_radix};
use tfhe::shortint::Ciphertext;
use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;

pub const NUM_BLOCK: usize = 4;

pub fn gen_rdx_keys() -> (RadixClientKey, ServerKey) {
    let (rdx_ck, rdx_sk) = gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, NUM_BLOCK);

    (rdx_ck, rdx_sk)
}

pub fn enc_rdx_vec(plain: &[u8], ck: &RadixClientKey) -> Vec<BaseRadixCiphertext<Ciphertext>> {
    let enc_ck: Vec<_> = plain
        .iter()
        .flat_map(|&byte| vec![ck.encrypt(byte)])
        .collect();

    enc_ck
}

pub fn dec_rdx_vec(enc: &[BaseRadixCiphertext<Ciphertext>], ck: &RadixClientKey) -> Vec<u8> {
    let plain: Vec<u8> = enc.iter().map(|c| ck.decrypt(c)).collect();

    plain
}

pub fn print_hex_rdx_fhe(
    label: &str,
    idx: usize,
    enc_data: &[BaseRadixCiphertext<Ciphertext>],
    ck: &RadixClientKey,
) {
    let state = dec_rdx_vec(enc_data, ck);

    let hex_output: String = state
        .iter()
        .map(|byte| format!("{:02x}", byte))
        .collect::<Vec<String>>()
        .join("");

    println!("{}  [{}] {}", label, idx, hex_output);
}
