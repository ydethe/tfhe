# tfhe-nand-poc

A minimal proof-of-concept demonstrating **Fully Homomorphic Encryption (FHE)**
in Rust with the [TFHE-rs](https://github.com/zama-ai/tfhe-rs) library.

It encrypts data, computes homomorphically **on the encrypted data without any
secret key**, then decrypts to verify correctness. On top of the classic FHE
demo it also shows **proxy re-encryption**: a semi-trusted server can re-encrypt
one of Alice's ciphertexts so that **Bob** can decrypt it — while the server
**never learns the plaintext** and Bob never receives Alice's secret key.

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

## Sharing a ciphertext with Bob (proxy re-encryption)

FHE lets a server *compute* on ciphertexts, but by itself a ciphertext is only
decryptable by the key that produced it. To **share** encrypted data with
another party without decrypting it, we use a **re-encryption key**
(`KeySwitchingKey` in TFHE-rs).

```
   Alice ──[ ct_A , rk_{A→B} ]──▶  Server  ──[ ct_B ]──▶  Bob
   (owner)                       (semi-trusted,          (recipient,
                                  no secret key)          own key)
```

| Step | Side | What happens |
|------|------|--------------|
| `generate_keys` | Alice / Bob | Each party has an independent key pair (same crypto parameters) |
| `KeySwitchingKey::new((alice…),(bob…))` | trusted setup | Builds the re-encryption key `rk_{A→B}`. It contains **no usable decryption secret** |
| `keyswitch(ct_A)` | **server** | Homomorphically re-encrypts `ct_A` into `ct_B`, decryptable by Bob. The server never sees the plaintext |
| `ct_B.decrypt(&bob_key)` | Bob | Recovers Alice's value with **his own** key |

Key properties demonstrated in `main.rs`:

- The server holds only the ciphertext and the re-encryption key — **no secret
  key of any kind** — and never sees the cleartext.
- Bob decrypts with his **own** key; he never receives Alice's secret key.
- Alice's key **cannot** decrypt the re-encrypted ciphertext (it is bound to
  Bob's key) — verified with an assertion.
- **Full FHE is preserved**: after re-encryption the server can keep computing
  homomorphically on Bob's ciphertext (the PoC computes `2 × secret`).

> Note: in this PoC the re-encryption key is built in-process for clarity, which
> requires access to both key pairs. In a real deployment this one-time setup is
> performed during a trusted handshake between Alice and Bob (or via a secure
> multi-party protocol); only the resulting re-encryption key is handed to the
> server.

## License

MIT
