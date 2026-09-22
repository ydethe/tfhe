use tfhe::prelude::*;
use tfhe::{
    generate_keys, set_server_key, ConfigBuilder, FheUint32, FheUint64, KeySwitchingKey,
};

fn main() {
    // ---------------------------------------------------------------------
    // PART 1 — Classic FHE: compute on encrypted data (Alice ⇄ Server)
    //
    // The full homomorphic capability is unchanged: Alice encrypts, the
    // server evaluates on ciphertexts without any secret key, Alice decrypts.
    // ---------------------------------------------------------------------

    // Key generation (Alice, client side).
    let config = ConfigBuilder::default().build();
    let (alice_key, alice_server_key) = generate_keys(config);

    // The server key carries no secret. It is installed into the current
    // thread so the homomorphic operations below can run.
    set_server_key(alice_server_key.clone());

    let clear_a: u64 = 37;
    let clear_b: u64 = 5;

    // Encrypt — client side only.
    let a = FheUint64::encrypt(clear_a, &alice_key);
    let b = FheUint64::encrypt(clear_b, &alice_key);

    println!("  Size of clear a: {} bytes", std::mem::size_of_val(&clear_a));
    println!("  Size of encrypted a: {} bytes", std::mem::size_of_val(&a));

    // Homomorphic arithmetic — server side, on ciphertexts, no secret key.
    let sum = &a + &b; // 42
    let diff = &a - &b; // 32
    let prod = &a * &b; // 185
    let anded = &a & &b; // bitwise AND: 5

    println!("  Size of encrypted sum: {} bytes", std::mem::size_of_val(&sum));

    // Decrypt — client side only.
    let sum_dec: u64 = sum.decrypt(&alice_key);
    let diff_dec: u64 = diff.decrypt(&alice_key);
    let prod_dec: u64 = prod.decrypt(&alice_key);
    let and_dec: u64 = anded.decrypt(&alice_key);

    assert_eq!(sum_dec, clear_a.wrapping_add(clear_b));
    assert_eq!(diff_dec, clear_a.wrapping_sub(clear_b));
    assert_eq!(prod_dec, clear_a.wrapping_mul(clear_b));
    assert_eq!(and_dec, clear_a & clear_b);

    println!("FheUint64 arithmetic on encrypted data:");
    println!("  {clear_a} + {clear_b} = {sum_dec}");
    println!("  {clear_a} - {clear_b} = {diff_dec}");
    println!("  {clear_a} * {clear_b} = {prod_dec}");
    println!("  {clear_a} & {clear_b} = {and_dec}");

    // A data-dependent comparison producing an encrypted boolean.
    let is_greater = a.gt(&b); // FheBool
    let is_greater_dec: bool = is_greater.decrypt(&alice_key);
    assert_eq!(is_greater_dec, clear_a > clear_b);
    println!("  {clear_a} > {clear_b} = {is_greater_dec}");

    // 32-bit arithmetic, mixing ciphertext with a clear scalar.
    let clear_x: u32 = 1_000_000;
    let x = FheUint32::encrypt(clear_x, &alice_key);
    let scaled = &x * 3u32 + 7u32; // scalar ops don't require encrypting the constant
    let scaled_dec: u32 = scaled.decrypt(&alice_key);
    assert_eq!(scaled_dec, clear_x.wrapping_mul(3).wrapping_add(7));
    println!("FheUint32 with clear scalars:");
    println!("  {clear_x} * 3 + 7 = {scaled_dec}");

    println!("All results verified homomorphically.\n");

    // ---------------------------------------------------------------------
    // PART 2 — Proxy re-encryption: share a ciphertext with Bob
    //
    // Goal: Alice wants Bob to be able to decrypt one of her ciphertexts,
    // WITHOUT ever revealing the plaintext to the server, and without giving
    // Bob her secret key. A semi-trusted server transforms the ciphertext
    // from "encrypted under Alice's key" to "encrypted under Bob's key".
    //
    //   Alice ──[ct_A, rk_{A→B}]──▶  Server  ──[ct_B]──▶  Bob
    //
    // The primitive that makes this possible in TFHE-rs is the
    // KeySwitchingKey (a.k.a. re-encryption key). Applying it homomorphically
    // re-encrypts a ciphertext under a different secret key. The server that
    // performs the operation learns nothing about the plaintext: it only ever
    // manipulates ciphertexts and a re-encryption key that contains no usable
    // decryption secret.
    // ---------------------------------------------------------------------

    // --- Bob generates his OWN independent key pair (client side, Bob). ---
    // Both parties must agree on the same cryptographic parameters, which is
    // guaranteed here since both derive from `ConfigBuilder::default()`.
    let (bob_key, bob_server_key) = generate_keys(config);

    // --- The secret value Alice wants to share with Bob (and nobody else). -
    let clear_secret: u64 = 123_456_789;
    let secret_ct_alice = FheUint64::encrypt(clear_secret, &alice_key);

    // --- Build the re-encryption key rk_{A→B}. ---------------------------
    // This is a one-time setup between Alice and Bob. It requires knowledge of
    // both secret keys, so in a real deployment it is produced during a
    // trusted handshake (or via a secure multi-party protocol) — NOT by the
    // server. Once created, the re-encryption key on its own cannot decrypt
    // anything; it can only transform Alice-ciphertexts into Bob-ciphertexts.
    let reencryption_key = KeySwitchingKey::new(
        (&alice_key, &alice_server_key), // from: Alice
        (&bob_key, &bob_server_key),     // to:   Bob
    )
    .expect("Alice and Bob share compatible parameters");

    // --- SERVER SIDE: proxy re-encryption. -------------------------------
    // The server is given ONLY `secret_ct_alice` and `reencryption_key`.
    // It has no client (secret) key of any kind. It re-encrypts the
    // ciphertext so that it is now decryptable by Bob. At no point does the
    // server see the plaintext.
    let secret_ct_bob: FheUint64 = server_reencrypt(&reencryption_key, &secret_ct_alice);

    // --- BOB SIDE: decrypt with Bob's own key. ---------------------------
    let bob_recovered: u64 = secret_ct_bob.decrypt(&bob_key);
    assert_eq!(bob_recovered, clear_secret);
    println!("Proxy re-encryption (Alice ──server──▶ Bob):");
    println!("  Alice's secret               : {clear_secret}");
    println!("  Recovered by Bob after re-enc: {bob_recovered}");

    // --- Sanity check: Alice's key can NOT decrypt Bob's ciphertext. -----
    // The re-encrypted ciphertext really is bound to Bob's secret key.
    let alice_tries: u64 = secret_ct_bob.decrypt(&alice_key);
    assert_ne!(
        alice_tries, clear_secret,
        "re-encrypted ciphertext must not decrypt under Alice's key"
    );
    println!("  Alice decrypting Bob's ct    : {alice_tries} (garbage, as expected)");

    // ---------------------------------------------------------------------
    // PART 3 — Full FHE capability is preserved for the recipient.
    //
    // The shared ciphertext is a first-class FHE ciphertext under Bob's key.
    // The server can keep computing on it homomorphically using Bob's server
    // key — still without ever seeing the plaintext.
    // ---------------------------------------------------------------------
    set_server_key(bob_server_key);
    let doubled = &secret_ct_bob + &secret_ct_bob; // homomorphic, under Bob's key
    let doubled_dec: u64 = doubled.decrypt(&bob_key);
    assert_eq!(doubled_dec, clear_secret.wrapping_mul(2));
    println!("  Server computes 2×secret on Bob's ct, Bob decrypts: {doubled_dec}");

    println!("\nShared ciphertext successfully re-encrypted; server never saw the plaintext.");
}

/// SERVER-SIDE operation. Takes a ciphertext encrypted under the *source*
/// secret key and a re-encryption key, and returns a ciphertext of the same
/// value encrypted under the *destination* secret key.
///
/// This function has access to no secret key. It cannot learn the plaintext.
fn server_reencrypt(reencryption_key: &KeySwitchingKey, ct: &FheUint64) -> FheUint64 {
    reencryption_key.keyswitch(ct)
}
