use tfhe::boolean::prelude::*;

fn main() {
    // Key generation
    let (client_key, server_key) = gen_keys();

    // Encrypt two bits
    let ct_a = client_key.encrypt(true);
    let ct_b = client_key.encrypt(false);

    // Homomorphic NAND — server side, no key needed
    let ct_nand = server_key.nand(&ct_a, &ct_b);

    // Decrypt — client side only
    let result = client_key.decrypt(&ct_nand);
    assert_eq!(result, true); // NAND(1,0) = 1

    println!("NAND(1, 0) = {result} (verified homomorphically)");
}
