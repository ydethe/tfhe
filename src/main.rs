use tfhe::prelude::*;
use tfhe::{generate_keys, set_server_key, ConfigBuilder, FheUint8, FheUint32};

fn main() {
    // Key generation (client side).
    let config = ConfigBuilder::default().build();
    let (client_key, server_key) = generate_keys(config);

    // The server key is what allows homomorphic evaluation. It carries no
    // secret and is installed into the current thread for the operations below.
    set_server_key(server_key);

    // --- 8-bit arithmetic (values 0..=255) --------------------------------
    let clear_a: u8 = 37;
    let clear_b: u8 = 5;

    // Encrypt — client side only.
    let a = FheUint8::encrypt(clear_a, &client_key);
    let b = FheUint8::encrypt(clear_b, &client_key);

    println!("  Size of clear a: {} bytes", std::mem::size_of_val(&clear_a));
    println!("  Size of encrypted a: {} bytes", std::mem::size_of_val(&a));
    
    // Homomorphic arithmetic — server side, on ciphertexts, no secret key.
    let sum = &a + &b; // 42
    let diff = &a - &b; // 32
    let prod = &a * &b; // 185
    let anded = &a & &b; // bitwise AND: 5

    println!("  Size of encrypted sum: {} bytes", std::mem::size_of_val(&sum));

    // Decrypt — client side only.
    let sum_dec: u8 = sum.decrypt(&client_key);
    let diff_dec: u8 = diff.decrypt(&client_key);
    let prod_dec: u8 = prod.decrypt(&client_key);
    let and_dec: u8 = anded.decrypt(&client_key);

    assert_eq!(sum_dec, clear_a.wrapping_add(clear_b));
    assert_eq!(diff_dec, clear_a.wrapping_sub(clear_b));
    assert_eq!(prod_dec, clear_a.wrapping_mul(clear_b));
    assert_eq!(and_dec, clear_a & clear_b);

    println!("FheUint8 arithmetic on encrypted data:");
    println!("  {clear_a} + {clear_b} = {sum_dec}");
    println!("  {clear_a} - {clear_b} = {diff_dec}");
    println!("  {clear_a} * {clear_b} = {prod_dec}");
    println!("  {clear_a} & {clear_b} = {and_dec}");

    // --- A data-dependent comparison producing an encrypted boolean -------
    let is_greater = a.gt(&b); // FheBool
    let is_greater_dec: bool = is_greater.decrypt(&client_key);
    assert_eq!(is_greater_dec, clear_a > clear_b);
    println!("  {clear_a} > {clear_b} = {is_greater_dec}");

    // --- 32-bit arithmetic, mixing ciphertext with a clear scalar ---------
    let clear_x: u32 = 1_000_000;
    let x = FheUint32::encrypt(clear_x, &client_key);
    let scaled = &x * 3u32 + 7u32; // scalar ops don't require encrypting the constant
    let scaled_dec: u32 = scaled.decrypt(&client_key);
    assert_eq!(scaled_dec, clear_x.wrapping_mul(3).wrapping_add(7));
    println!("FheUint32 with clear scalars:");
    println!("  {clear_x} * 3 + 7 = {scaled_dec}");

    println!("All results verified homomorphically.");
}
