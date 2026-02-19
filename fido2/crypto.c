// SPDX-FileCopyrightText: 2019 SoloKeys Developers
// SPDX-FileCopyrightText: 2025 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: Apache-2.0 OR MIT

/*
 *  Wrapper for crypto implementation on device.
 *
 *  Can be replaced with different crypto implementation by
 *  defining EXTERNAL_SOLO_CRYPTO
 *
 * */
#ifndef EXTERNAL_SOLO_CRYPTO

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto.h"
#include "util.h"

#include "aes.h"
#include "ctap.h"
#include "device.h"
#include "sha256.h"
#include "uECC.h"
// stuff for SHA512
#include "blockwise.h"
#include "sha2.h"
#include APP_CONFIG
#include "log.h"

#define crypto_sign_ed25519_PUBLICKEYBYTES 32
#define crypto_sign_ed25519_SECRETKEYBYTES 64
#define crypto_sign_ed25519_SEEDBYTES 32

#include "monocypher-ed25519.h"

static SHA256_CTX sha256_ctx;
static cf_sha512_context sha512_ctx;
static const struct uECC_Curve_t *_es256_curve = NULL;
static const uint8_t *_signing_key = NULL;
static int _key_len = 0;

// Secrets for testing only
static uint8_t master_secret[64];
static uint8_t transport_secret[32];

const uint8_t *crypto_get_key_transport(uint8_t *len)
{
	*len = sizeof(transport_secret);
	return transport_secret;
}

void crypto_sha256_init(void)
{
	sha256_init(&sha256_ctx);
}

void fido2_crypto_sha512_init(void)
{
	cf_sha512_init(&sha512_ctx);
}

void crypto_load_master_secret(uint8_t *key)
{
#if KEY_SPACE_BYTES < 96
#error "need more key bytes"
#endif
	memmove(master_secret, key, 64);
	memmove(transport_secret, key + 64, 32);
}

void crypto_reset_master_secret(void)
{
	memset(master_secret, 0, 64);
	memset(transport_secret, 0, 32);
	ctap_generate_rng(master_secret, 64);
	ctap_generate_rng(transport_secret, 32);
}

void crypto_sha256_update(uint8_t *data, size_t len)
{
	sha256_update(&sha256_ctx, data, len);
}

void fido2_crypto_sha512_update(const uint8_t *data, size_t len)
{
	cf_sha512_update(&sha512_ctx, data, len);
}

void crypto_sha256_update_secret()
{
	sha256_update(&sha256_ctx, master_secret, 32);
}

void crypto_sha256_final(uint8_t *hash)
{
	sha256_final(&sha256_ctx, hash);
}

void crypto_sha256(uint8_t *digest, uint8_t *data, size_t len)
{
	SHA256_CTX ctx;
	sha256_init(&ctx);
	sha256_update(&ctx, data, len);
	sha256_final(&ctx, digest);
}

void fido2_crypto_sha512_final(uint8_t *hash)
{
	// NB: there is also cf_sha512_digest
	cf_sha512_digest_final(&sha512_ctx, hash);
}

void crypto_sha256_hmac_init(const uint8_t *key, uint32_t klen)
{
	uint8_t buf[64];
	unsigned int i;
	memset(buf, 0, sizeof(buf));

	if (klen > 64) {
		printf2(TAG_ERR, "Error, key size must be <= 64\n");
		exit(1);
	}

	memmove(buf, key, klen);

	for (i = 0; i < sizeof(buf); i++) {
		buf[i] = buf[i] ^ 0x36;
	}

	crypto_sha256_init();
	crypto_sha256_update(buf, 64);
}

void crypto_sha256_hmac_final(const uint8_t *key, uint32_t klen, uint8_t *hmac)
{
	uint8_t buf[64];
	unsigned int i;
	crypto_sha256_final(hmac);
	memset(buf, 0, sizeof(buf));

	if (klen > 64) {
		printf2(TAG_ERR, "Error, key size must be <= 64\n");
		exit(1);
	}
	memmove(buf, key, klen);

	for (i = 0; i < sizeof(buf); i++) {
		buf[i] = buf[i] ^ 0x5c;
	}

	crypto_sha256_init();
	crypto_sha256_update(buf, 64);
	crypto_sha256_update(hmac, 32);
	crypto_sha256_final(hmac);
}

void crypto_ecc256_init(void)
{
	uECC_set_rng((uECC_RNG_Function)ctap_generate_rng);
	_es256_curve = uECC_secp256r1();
}

void crypto_ecc256_load_attestation_key(void)
{
	_signing_key = device_get_attestation_key();
	_key_len = 32;
}

void crypto_ecc256_sign(uint8_t *data, int len, uint8_t *sig)
{
	if (uECC_sign(_signing_key, data, len, sig, _es256_curve) == 0) {
		printf2(TAG_ERR, "error, uECC failed\n");
		exit(1);
	}
}

void crypto_ecc256_load_key(uint8_t *data, int len, uint8_t *data2, int len2)
{
	static uint8_t privkey[32];
	generate_private_key(data, len, data2, len2, privkey);
	_signing_key = privkey;
	_key_len = 32;
}

void generate_private_key(uint8_t *data, int len, uint8_t *data2, int len2,
			  uint8_t *privkey)
{
	crypto_sha256_hmac_init(master_secret, 32);
	crypto_sha256_update(data, len);
	crypto_sha256_update(data2, len2);
	crypto_sha256_update(master_secret, 32); // TODO AES
	crypto_sha256_hmac_final(master_secret, 32, privkey);

	crypto_aes256_init(master_secret + 32, NULL);
	crypto_aes256_encrypt(privkey, 32);
}

/*int uECC_compute_public_key(const uint8_t *private_key, uint8_t *public_key,
 * uECC_Curve curve);*/
void crypto_ecc256_derive_public_key(uint8_t *data, int len, uint8_t *x,
				     uint8_t *y)
{
	uint8_t privkey[32];
	uint8_t pubkey[64];

	generate_private_key(data, len, NULL, 0, privkey);

	memset(pubkey, 0, sizeof(pubkey));
	uECC_compute_public_key(privkey, pubkey, _es256_curve);
	memmove(x, pubkey, 32);
	memmove(y, pubkey + 32, 32);
}
void crypto_ecc256_compute_public_key(uint8_t *privkey, uint8_t *pubkey)
{
	uECC_compute_public_key(privkey, pubkey, _es256_curve);
}

void crypto_load_external_key(uint8_t *key, int len)
{
	_signing_key = key;
	_key_len = len;
}

void crypto_ecc256_make_key_pair(uint8_t *pubkey, uint8_t *privkey)
{
	if (uECC_make_key(pubkey, privkey, _es256_curve) != 1) {
		printf2(TAG_ERR, "Error, uECC_make_key failed\n");
		exit(1);
	}
}

void crypto_ecc256_shared_secret(const uint8_t *pubkey, const uint8_t *privkey,
				 uint8_t *shared_secret)
{
	if (uECC_shared_secret(pubkey, privkey, shared_secret, _es256_curve) !=
	    1) {
		printf2(TAG_ERR, "Error, uECC_shared_secret failed\n");
		exit(1);
	}
}

struct AES_ctx aes_ctx;
void crypto_aes256_init(uint8_t *key, uint8_t *nonce)
{
	AES_init_ctx(&aes_ctx, key);

	if (nonce == NULL) {
		memset(aes_ctx.Iv, 0, 16);
	} else {
		memmove(aes_ctx.Iv, nonce, 16);
	}
}

// prevent round key recomputation
void crypto_aes256_reset_iv(uint8_t *nonce)
{
	if (nonce == NULL) {
		memset(aes_ctx.Iv, 0, 16);
	} else {
		memmove(aes_ctx.Iv, nonce, 16);
	}
}

void crypto_aes256_decrypt(uint8_t *buf, int length)
{
	AES_CBC_decrypt_buffer(&aes_ctx, buf, length);
}

void crypto_aes256_encrypt(uint8_t *buf, int length)
{
	AES_CBC_encrypt_buffer(&aes_ctx, buf, length);
}

void fido2_crypto_ed25519_derive_public_key(uint8_t *data, int len, uint8_t *x)
{
	uint8_t seed[crypto_sign_ed25519_SEEDBYTES];
	uint8_t sk[crypto_sign_ed25519_SECRETKEYBYTES];

	generate_private_key(data, len, NULL, 0, seed);
	crypto_ed25519_key_pair(sk, x, seed);
}

void fido2_crypto_ed25519_load_key(uint8_t *data, int len)
{
	uint8_t seed[crypto_sign_ed25519_SEEDBYTES];
	uint8_t pk[crypto_sign_ed25519_PUBLICKEYBYTES];
	static uint8_t sk[crypto_sign_ed25519_SECRETKEYBYTES];

	generate_private_key(data, len, NULL, 0, seed);
	crypto_ed25519_key_pair(sk, pk, seed);

	_signing_key = sk;
	_key_len = crypto_sign_ed25519_SECRETKEYBYTES;
}

void fido2_crypto_ed25519_sign(uint8_t *data1, int len1, uint8_t *data2,
			       int len2, uint8_t *sig)
{
	// ed25519 signature APIs need the message at once (by design!) and in
	// one contiguous buffer (could be changed).

	// 512 is an arbitrary sanity limit, could be less
	if (len1 < 0 || len2 < 0 || len1 > 512 || len2 > 512) {
		memset(sig, 0, 64); // ed25519 signature len is 64 bytes
		return;
	}
	// XXX: dynamically sized allocation on the stack
	const int len = len1 + len2; // 0 <= len <= 1024
	uint8_t data[len1 + len2];

	memcpy(data, data1, len1);
	memcpy(data + len1, data2, len2);

	// TODO: check that correct load_key() had been called?
	crypto_ed25519_sign(sig, _signing_key, data, len);
}

#endif
