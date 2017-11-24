# pbp - Pretty Bad Protocol

The predominant system for signing data today is the OpenPGP format, defined in
IETF RFC 4880. However, this is spec is very complex, and its primary
implementation (gpg, or Gnu Privacy Guard) is a heavyweight dependency. It can
be desirable to have be able to sign data in contexts in which depending on gpg
or reimplementing OpenPGP would be a poor decision.

Because of the dominance of OpenPGP, many media for transmitting public keys
assume the key is an OpenPGP formatted key. This can make it difficult to
implement signature verification systems distinct from OpenPGP.

This library generates a valid OpenPGP public key datagram from any ed25519
public key. It also parses OpenPGP public keys enough to retrieve an ed25519
public key from that data. This way, users can exchange public keys through
systems which only accept OpenPGP keys, even if the system they are using to
sign their data is not a full OpenPGP implementation.

This library's default API is unopinionated about which implementation of
ed25519 you use. However, it has an optional dependency on
[ed25519-dalek][dalek] which provides a slightly nicer API using the types from
that library.

## Demonstration

The "print" example prints an ASCII armored OpenPGP public key to stdout; you
can check that using:

```
$ cargo run --features dalek --example print
```

[dalek]: https://github.com/isislovecruft/ed25519-dalek
