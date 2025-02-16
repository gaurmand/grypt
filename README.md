# grypt

#### What is this?
An OpenSSL C++ wrapper.

#### Why did you make this?
To learn more about OpenSSL and cryptography.

#### Does it work?
Yeah kinda.

## Status
- [x] Symmetric cipher
  - [ ] Add support for more non-AES ciphers
  - [ ] Add options for variable length keys & ivs
- [x] Authenticated symmetric cipher
  - [ ] Add GCM-SIV support
- [x] Asymmetric cipher
  - [ ] Add SM2 support? is this even possible
  - [ ] Add options for RSA OAEP and MGF1
- [x] Hash
  - [ ] Add XOF support
- [x] MAC
  - [ ] Add XOF support
  - [ ] Add Poly1305 support? seems complicated
- [x] Digital Signatures
  - [ ] Figure out why RSA no padding and X931 padding don't work
  - [ ] RSA PSS works?
  - [ ] Add ML-DSA support
- [ ] Key Exchange
- [ ] KDF
- [ ] Keygen
- [ ] Misc
  - [ ] Refactor pkey code into shared infra
  - [ ] Refactor algorithm info code (fetch info with context vs without)
  - [ ] Calculating input/output sizes (RSA_size() or EVP_pkey_get_size())
  - [ ] State transitions match EVP lifecycles?
  - [ ] Possible to set EVP parameters once instead of at start of each operation? Is there a benefit?
