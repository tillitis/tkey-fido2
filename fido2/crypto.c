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

static uint8_t key_cred_priv[32];
static uint8_t key_cred_mac[32];
static uint8_t key_meta_enc[32];
static uint8_t key_hmac_ext[32];

const uint8_t *crypto_get_key_mac(uint8_t *len)
{
	*len = sizeof(key_cred_mac);
	return key_cred_mac;
}

const uint8_t *crypto_get_key_meta(uint8_t *len)
{
	*len = sizeof(key_meta_enc);
	return key_meta_enc;
}

const uint8_t *crypto_get_key_hmac(uint8_t *len)
{
	*len = sizeof(key_hmac_ext);
	return key_hmac_ext;
}

void crypto_sha256_init(void)
{
	sha256_init(&sha256_ctx);
}

void fido2_crypto_sha512_init(void)
{
	cf_sha512_init(&sha512_ctx);
}

void crypto_derive_device_keys(uint8_t *salt, uint8_t salt_size)
{
	// Derives the keys with HKDF-SHA256 based on a non-secret salt, a
	// device bound hardware secret and domain separation.

	const uint8_t *device_secret = device_get_bound_secret();
	uint8_t prk[32] = {0x00};

	crypto_hkdf_extract_sha256(salt, salt_size, device_secret, 32, prk);

	static const uint8_t info_cred_priv[] = "cred_priv";
	static const uint8_t info_cred_mac[] = "cred_mac";
	static const uint8_t info_meta_enc[] = "meta_enc";
	static const uint8_t info_hmac_ext[] = "hmac_ext";

	crypto_hkdf_expand_sha256(prk, info_cred_priv, sizeof(info_cred_priv),
				  key_cred_priv, sizeof(key_cred_priv));

	crypto_hkdf_expand_sha256(prk, info_cred_mac, sizeof(info_cred_mac),
				  key_cred_mac, sizeof(key_cred_mac));

	crypto_hkdf_expand_sha256(prk, info_meta_enc, sizeof(info_meta_enc),
				  key_meta_enc, sizeof(key_meta_enc));

	crypto_hkdf_expand_sha256(prk, info_hmac_ext, sizeof(info_hmac_ext),
				  key_hmac_ext, sizeof(key_hmac_ext));

	secure_wipe(prk, sizeof(prk));
}

void crypto_sha256_update(const uint8_t *data, size_t len)
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

void crypto_sha256(uint8_t *digest, const uint8_t *data, size_t len)
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
	crypto_derive_credential_key(data, len, data2, len2, privkey);
	_signing_key = privkey;
	_key_len = 32;
}

// HKDF-SHA256 inspired by RFC 5869.
// The extract and expand phases are provided as two functions.
//
// Use crypto_hkdf_extract_sha256 for the extract phase, with an optional salt.
// Set salt=NULL and/or salt_len=0 to use the RFC-defined zero salt.
// salt_len must be <= 64 bytes. ikm is the input keying material.
// Returns the prk, which should be used as an input in the expand phase.
//
// Use crypto_hkdf_expand_sha256 for the expand phase, to generate up to 255
// bytes of key material into okm. okm_len must be <= 255 bytes.
//
// Info is strongly recommended for domain separation.
//
// No input validation is performed; it is the caller's responsibility.

void crypto_hkdf_extract_sha256(const uint8_t *salt, uint8_t salt_len,
				const uint8_t *ikm, uint8_t ikm_len,
				uint8_t prk[32])
{
	// PRK = HMAC(salt, input_key_material)

	const uint8_t zero_salt[32] = {0};

	if (salt == NULL || salt_len == 0) {
		salt = zero_salt;
		salt_len = sizeof(zero_salt);
	}

	crypto_sha256_hmac_init(salt, salt_len);
	crypto_sha256_update(ikm, ikm_len);
	crypto_sha256_hmac_final(salt, salt_len, prk);
}

void crypto_hkdf_expand_sha256(const uint8_t prk[32], const uint8_t *info,
			       uint8_t info_len, uint8_t *okm, uint8_t okm_len)
{
	// T(0) = empty string (zero length)
	// T(i) = HMAC(PRK, T(i−1) || info || counter)

	uint8_t remaining = okm_len;
	uint8_t t[32] = {0x00};
	uint8_t t_len = 0;
	uint8_t counter = 1;
	uint8_t copied = 0;
	uint8_t to_copy = 0;

	while (remaining > 0) {

		crypto_sha256_hmac_init(prk, 32);
		crypto_sha256_update(t, t_len);
		crypto_sha256_update((const uint8_t *)info, info_len);
		crypto_sha256_update(&counter, 1);
		crypto_sha256_hmac_final(prk, 32, t);

		to_copy = remaining;
		if (to_copy > 32) {
			to_copy = 32;
		}
		memcpy(okm + copied, t, to_copy);
		remaining -= to_copy;
		copied += to_copy;
		counter++;
		t_len = 32;
	}
	secure_wipe(t, sizeof(t));
}

void crypto_derive_credential_key(uint8_t *data, int len, uint8_t *data2,
				  int len2, uint8_t *privkey)
{
	crypto_sha256_hmac_init(key_cred_priv, 32);
	crypto_sha256_update(data, len);
	crypto_sha256_update(data2, len2);
	crypto_sha256_update(key_cred_priv, 32); // TODO AES
	crypto_sha256_hmac_final(key_cred_priv, 32, privkey);
}

/*int uECC_compute_public_key(const uint8_t *private_key, uint8_t
 * *public_key, uECC_Curve curve);*/
void crypto_ecc256_derive_public_key(uint8_t *data, int len, uint8_t *x,
				     uint8_t *y)
{
	uint8_t privkey[32];
	uint8_t pubkey[64];

	crypto_derive_credential_key(data, len, NULL, 0, privkey);

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

	crypto_derive_credential_key(data, len, NULL, 0, seed);
	crypto_ed25519_key_pair(sk, x, seed);
}

void fido2_crypto_ed25519_load_key(uint8_t *data, int len)
{
	uint8_t seed[crypto_sign_ed25519_SEEDBYTES];
	uint8_t pk[crypto_sign_ed25519_PUBLICKEYBYTES];
	static uint8_t sk[crypto_sign_ed25519_SECRETKEYBYTES];

	crypto_derive_credential_key(data, len, NULL, 0, seed);
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
