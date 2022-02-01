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

## Usage

```
Usage:
    dashi --keygen [-o OUTPUT]
    dashi [--encrypt] [-i PATH] (-r RECIPIENT | -R PATH)... [--armor] [-o OUTPUT] [INPUT]
    dashi --decrypt [-i PATH]... [-o OUTPUT] [INPUT]
    dashi --sign [-o OUTPUT] [INPUT]
    dashi --verify [INPUT]

Options:
    -k, --keygen                Generate a key pair.
    -e, --encrypt               Encrypt the input to the output.
    -d, --decrypt               Decrypt the input to the output. Default if omitted.
    -s, --sign                  Sign the input to the output.
    -v, --verify                Verify the input.
    -o, --output OUTPUT         Write the result to the file at path OUTPUT.
    -a, --armor                 Encrypt/sign to a Base64 encoded format.
    -r, --recipient RECIPIENT   Encrypt to the specified RECIPIENT. Can be repeated.
    -R, --recipients-file PATH  Encrypt to recipients listed at PATH. Can be repeated.
    -i, --identity PATH         Use the identity file at PATH. Can be repeated with
		                            decrypt or verify.
    -n, --anon                  Encrypt to anonymous recipients with an anonymous
                                identity.
```

## TODO

* command line opts
* authenticated header
* compress text files
* encrypt/decrypt on multiple threads
* custom ChunkedReader to support variable-length chunks
* so many things
