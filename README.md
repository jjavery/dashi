# dashi

Simple elliptic curve public key encryption and signing built on libsodium and
*heavily* influenced by [age](age-encryption.org)

**Please don't use ```dashi``` for anything important!** It's a project I'm
working on in my spare time with the goals of learning Go and gaining a better
understanding of libsodium. Use [age](age-encryption.org) and
[minisign](jedisct1.github.io/minisign/) instead.

* Uses Ed25519 signing keys for both signing and encryption.
[seems legit?](https://eprint.iacr.org/2021/509.pdf)
* Encryption always signs both plaintext and ciphertext.
[why?](https://theworld.com/~dtd/sign_encrypt/sign_encrypt7.html)
* All cryptography via [libsodium](https://libsodium.gitbook.io/doc/) primitives.
* Text files are compressed

## TODO

* so many things
* encrypt/decrypt on multiple threads
