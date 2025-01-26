# Design

- **Readable:** Close to the FIPS-197 documentation.
- **Encrypt/decrypt:** Both operations supported. Each block outsourced to the server/cloud.
- **Thread-safe:** Only static global variables
- **Efficient Implementation:**
  - Minimize bootstraps, as they dominate runtime.
  - Use BooleanBlock for the `S-Box`, with boolean circuit evaluation. 
  - Use MatchValues for the `MixColumns` step.
- **xor:** Performed unchecked() since bitlength is known.
- **mix_col:**
   - Operations are decomposed.
   - Example: The complete g2 state and g3 state are first retrieved, and the g2_g3_xor state afterwards. 
- **Key Expansion:** 
  - Performed as an offline phase.
  - Additional tables for combined operations can be precomputed.
- **Parallelism:**
  - Support for 16 threads throughput, one per state.
- **Mode of Operation:**
   - Cipher mode OFB (Output Feedback) style, to XOR the stream.
   - `Encrypt(IV/the_message, key) -> Encrypt(#, key)`

### State matrix indices
#### byte layout

| Row/Col | 0  | 1  | 2  | 3  |
|---------|----|----|----|----|
| **0**   | 0  | 4  | 8  | 12 |
| **1**   | 1  | 5  | 9  | 13 |
| **2**   | 2  | 6  | 10 | 14 |
| **3**   | 3  | 7  | 11 | 15 |

## PBS
### PBS per operation

| Operation    | PBS Count | PBS / thread | Details              |
|--------------|-----------|--------------|----------------------|
| **add_key**  | 16        | 1            | bitwise XOR          |
| **sub_**     | 16        | 1            | bitwise XOR          |
| **rot_rows** | 0         | 0            |                      |
| **mix_cols** | 80        | 5            | Two LUTs, three XORs |

### PBS encrypt
Time taken can be estimated from

| Operation    | Tot. operations | PBS / thread | 
|--------------|-----------------|--------------|
| **add_key**  | 11              | 11           |
| **sub_**     | 10              | 10           |
| **rot_rows** | 10              | 0            |
| **mix_cols** | 9 * 5           | 45           |
| **Total**    | **76**          | **66**       |      


## Example Invocation
### Binary
```bash
cargo run --release -- --help

Usage: aes128_rdx_bc_fhe [OPTIONS]

Options:
  -n, --number-of-outputs <number_of_outputs>
          Sets the number of blocks [default: 1]
  -i, --initialization-vector <iv>
          Initialization vector [default: 00112233445566778899aabbccddeeff]
  -k, --key <key>
          Key value [default: 000102030405060708090a0b0c0d0e0f]
  -h, --help
          Print help
  -V, --version
          Print version
```

```bash
cargo run --release -- -n 1 -i "00112233445566778899aabbccddeeff" -k "0123456789abcdef0123456789abcdef"
```

### Test suite
Running all the tests at once probably overloads the system.
```bash
cargo test --release -- --nocapture
```
Cherry-pick tests with
```
cargo test --release -- --nocapture ::test_endianess -- --exact
```

# References
- [NIST FIPS 197 (Original)](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.197.pdf)
- [NIST FIPS 197 (Update 1)](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf)
- [NIST Special Publication 800-38A](https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-38a.pdf)
- [A new combinational logic minimization technique with applications to cryptology.](https://eprint.iacr.org/2009/191.pdf)
- [Circuit Minimization Work. Yale]
