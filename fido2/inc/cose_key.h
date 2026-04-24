// SPDX-FileCopyrightText: 2019 SoloKeys Developers
// SPDX-License-Identifier: Apache-2.0 OR MIT

#ifndef _COSE_KEY_H_
#define _COSE_KEY_H_

#include <stdint.h>

#include "cbor.h"

// clang-format off
// COSE Key Common Parameters, https://www.iana.org/assignments/cose/cose.xhtml#key-common-parameters
#define COSE_KEY_LABEL_KTY   1 // Identification of the key type
#define COSE_KEY_LABEL_ALG   3 // Key usage restriction to this algorithm

// COSE Key Type Parameters, https://www.iana.org/assignments/cose/cose.xhtml#key-type-parameters
#define COSE_KEY_LABEL_CRV  -1 // EC identifier -- Taken from the "COSE Elliptic Curves" registry
#define COSE_KEY_LABEL_X    -2 // KTY=1 (OKP) -> Public Key, KTY=2 (EC2)-> x-coordinate
#define COSE_KEY_LABEL_Y    -3 //                            KTY=2 (EC2)-> y-coordinate

// COSE Key Types, https://www.iana.org/assignments/cose/cose.xhtml#key-type
#define COSE_KEY_KTY_OKP     1 // Octet Key Pair
#define COSE_KEY_KTY_EC2     2 // Elliptic Curve Keys w/ x- and y-coordinate pair

// COSE Elliptic Curves, https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves
#define COSE_KEY_CRV_P256    1 // NIST P-256 also known as secp256r1, KTY=2 (EC2)
#define COSE_KEY_CRV_ED25519 6 // Ed25519 for use w/ EdDSA only,      KTY=1 (OKP)

// COSE Algorithms, https://www.iana.org/assignments/cose/cose.xhtml#algorithms
#define COSE_ALG_ES256            -7  // ECDSA w/ SHA-256
#define COSE_ALG_EDDSA            -8  // EdDSA
#define COSE_ALG_ECDH_ES_HKDF_256 -25 // ECDH ES w/ HKDF - generate key directly
// clang-format on

typedef struct {
	struct {
		uint8_t x[32];
		uint8_t y[32];
	} pubkey;

	int kty;
	int crv;
} COSE_key;

int cose_key_add(CborEncoder *cose_key, uint8_t *x, uint8_t *y,
		 uint8_t credtype, int32_t algtype);
int cose_key_generate(CborEncoder *cose_key, uint8_t *hmac_input, int len,
		      uint8_t credtype, int32_t algtype);
uint8_t cose_key_parse(CborValue *it, COSE_key *cose);

#endif
