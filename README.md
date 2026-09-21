# tfhe-nand-poc

A minimal proof-of-concept demonstrating **Fully Homomorphic Encryption (FHE)**
in Rust with the [TFHE-rs](https://github.com/zama-ai/tfhe-rs) library.

It encrypts two bits, computes a homomorphic `NAND` **on the encrypted data
without any secret key**, then decrypts the result to verify correctness.

## Requirements

- Rust (stable) — `rustup` recommended
- A 64-bit x86 or ARM CPU (TFHE-rs requires a 64-bit platform)

## Run

```bash
cargo run --release
```

Expected output:

```
NAND(1, 0) = true (verified homomorphically)
```

> Use `--release`: FHE operations are extremely slow in a debug build.

## How it works

| Step | Side | What happens |
|------|------|--------------|
| `gen_keys()`        | client | Generates a `ClientKey` (secret) and `ServerKey` (public evaluation key) |
| `client_key.encrypt` | client | Encrypts each plaintext bit into a ciphertext |
| `server_key.nand`   | server | Evaluates NAND directly on ciphertexts — no secret key needed |
| `client_key.decrypt` | client | Recovers the plaintext result |

The server never sees the plaintext or the secret key, yet produces a correct
encrypted result.

## License

MIT
