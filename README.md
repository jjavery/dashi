# dashi

Simple elliptic curve public key encryption and signing built on libsodium and
*heavily* influenced by [age](https://age-encryption.org)

**Please don't use ```dashi``` for anything important!** It's a project I'm
working on in my spare time with the goals of learning Go and gaining a better
understanding of libsodium. Use [age](https://age-encryption.org) and
[minisign](https://jedisct1.github.io/minisign/) instead.

* Uses Ed25519 signing keys for both signing and encryption.
[seems legit?](https://eprint.iacr.org/2021/509.pdf)
* Encryption always signs both plaintext and ciphertext.
[why?](https://theworld.com/~dtd/sign_encrypt/sign_encrypt7.html)
* All cryptography via [libsodium](https://libsodium.gitbook.io/doc/) primitives.
* Text files are compressed
* MIME-style headers, easily parsed by Go's
[textproto.Reader](https://pkg.go.dev/net/textproto#Reader.ReadMIMEHeader)
* HTTP-style chunked encoding

## TODO

* command line opts
* authenticated header
* compress text files
* encrypt/decrypt on multiple threads
* custom ChunkedReader to support variable-length chunks
* so many things
