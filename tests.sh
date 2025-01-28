cargo test --release -- --nocapture ::test_key_expansion -- --exact
cargo test --release -- --nocapture ::test_init_arr_ciphertext ::test_init_vec_ciphertext -- --exact
cargo test --release -- --nocapture ::test_match_value_lookup_sbox_tfhe -- --exact
cargo test --release -- --nocapture ::test_perf_rdx_xor -- --exact
cargo test --release -- --nocapture ::test_encrypt_block_tfhe1 -- --exact
cargo test --release -- --nocapture ::test_decrypt_block_tfhe1 -- --exact
cargo test --release -- --nocapture ::test_encrypt_block_tfhe2 -- --exact
cargo test --release -- --nocapture ::test_decrypt_block_tfhe2 -- --exact
cargo test --release -- --nocapture ::test_encrypt_decrypt_rnd_block -- --exact
cargo test --release -- --nocapture ::test_sbox -- --exact
cargo test --release -- --nocapture ::test_mix -- --exact

cargo run --release -- -n 1 -i "00112233445566778899aabbccddeeff" -k "0123456789abcdef0123456789abcdef"
cargo run --release -- -n 2 -i "00112233445566778899aabbccddeeff" -k "0123456789abcdef0123456789abcdef"

echo "READY!"
