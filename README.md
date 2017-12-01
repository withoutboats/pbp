# pbp - Pretty Bad Protocol

This crate lets you print OpenPGP formatted public keys from ed25519 keys.

```rust
fn print_key(keypair: KeyPair) {
    let pgp_key = PgpKey::new(&keypair.public[..], "user id string", |data| {
        keypair.sign(data).to_bytes()
    });
    println!("{}", pgp_key);
}
```

It's agnostic about what library you use to implement ed25519, but it has a
feature which integrates with [ed25519-dalek][dalek]

Thanks to isis lovecruft and Henry de Valence for assistance with the dalek API
and understanding the OpenPGP specification.

## Demonstration

The "print" example prints an ASCII armored OpenPGP public key to stdout; you
can check that using:

```
$ cargo run --features dalek --example print
```

[dalek]: https://github.com/isislovecruft/ed25519-dalek
