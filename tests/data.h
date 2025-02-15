#ifndef GRYPT_TESTDATA_H
#define GRYPT_TESTDATA_H

#include <grypt/bytes.h>

extern const grypt::Bytes kRSAPublicKey2048;
extern const grypt::Bytes kRSAPrivateKey2048;

extern const grypt::Bytes kRSAPublicKey4096;
extern const grypt::Bytes kRSAPrivateKey4096;

extern const grypt::Bytes kDSAPublicKey2048;
extern const grypt::Bytes kDSAPrivateKey2048;

extern const grypt::Bytes kECPublicKey;
extern const grypt::Bytes kECPrivateKey;

extern const grypt::Bytes kED25519PublicKey;
extern const grypt::Bytes kEC25519PrivateKey;

extern const grypt::Bytes kED448PublicKey;
extern const grypt::Bytes kEC448PrivateKey;

#endif
