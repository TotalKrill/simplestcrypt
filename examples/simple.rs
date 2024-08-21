use std::str;
fn main() {
    let payload = "Hello world!".as_bytes();
    let password = b"hello wooooooooo";

    println!("Payload: {:?}", payload);
    let encrypted = simplestcrypt::encrypt_and_serialize(&password[..], &payload).unwrap();
    println!("Encrypted: {:?}", encrypted);
    let plain = simplestcrypt::deserialize_and_decrypt(&password[..], &encrypted).unwrap();

    println!("Decrypted: {:?}", &plain);
}
