# simplestcrypt

Simplest way to perform a symmetric encryption, using a preshared key. Very small wrapper around aes-siv crate, with randomly generated nonces, for anything more advanced, use aes-siv instead

## Example


``` rust
use std::str;
fn main() {
    let payload = "Hello world!".as_bytes();
    let password = b"hello wooooooooo";

    let encrypted = simplestcrypt::encrypt_and_serialize(&password[..], &payload).unwrap();
    let plain = simplestcrypt::deserialize_and_decrypt(&password[..], &encrypted).unwrap();

    println!("{:?}", str::from_utf8(&plain));
}
```

## Serialization notes

Bincode adds 8 bytes in between the serialized nonce and the serialized ciphertext so it looks like:

| Bytes   | Description                               |
| ------- | ----------------------------------------- |
| 0  - 15 | Nonce used when encrypting the ciphertext |
| 16 - 23 | The lenght of the cyphertext              |
| 24 - .. | Cyphertext                                |

This needs to be taken into account when interoperating with other libraries
