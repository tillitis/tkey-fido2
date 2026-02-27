// SPDX-FileCopyrightText: 2019 SoloKeys Developers
// SPDX-License-Identifier: Apache-2.0 OR MIT

#ifndef _CRYPTO_H
#define _CRYPTO_H

#include <stddef.h>
#include <stdint.h>

const uint8_t *crypto_get_key_mac(uint8_t *len);
const uint8_t *crypto_get_key_meta(uint8_t *len);
const uint8_t *crypto_get_key_hmac(uint8_t *len);

void crypto_sha256_init();
void crypto_sha256_update(const uint8_t *data, size_t len);
void crypto_sha256_final(uint8_t *hash);
void crypto_sha256(uint8_t *digest, const uint8_t *data, size_t len);

void crypto_sha256_hmac_init(const uint8_t *key, uint32_t klen);
void crypto_sha256_hmac_final(const uint8_t *key, uint32_t klen, uint8_t *hmac);

void crypto_hkdf_extract_sha256(const uint8_t *salt, uint8_t salt_len,
				const uint8_t *ikm, uint8_t ikm_len,
				uint8_t prk[32]);
void crypto_hkdf_expand_sha256(const uint8_t prk[32], const uint8_t *info,
			       uint8_t info_len, uint8_t *out, uint8_t out_len);

void fido2_crypto_sha512_init();
void fido2_crypto_sha512_update(const uint8_t *data, size_t len);
void fido2_crypto_sha512_final(uint8_t *hash);

void crypto_ecc256_init();
void crypto_ecc256_derive_public_key(uint8_t *data, int len, uint8_t *x,
				     uint8_t *y);
void crypto_ecc256_compute_public_key(uint8_t *privkey, uint8_t *pubkey);

void crypto_ecc256_load_key(uint8_t *data, int len, uint8_t *data2, int len2);
void crypto_ecc256_load_attestation_key();
void crypto_load_external_key(uint8_t *key, int len);
void crypto_ecc256_sign(uint8_t *data, int len, uint8_t *sig);
void crypto_ecdsa_sign(uint8_t *data, int len, uint8_t *sig,
		       int MBEDTLS_ECP_ID);

void fido2_crypto_ed25519_derive_public_key(uint8_t *data, int len, uint8_t *x);
void fido2_crypto_ed25519_sign(uint8_t *data1, int len1, uint8_t *data2,
			       int len2, uint8_t *sig);
void fido2_crypto_ed25519_load_key(uint8_t *data, int len);

void crypto_derive_credential_key(uint8_t *data, int len, uint8_t *data2,
				  int len2, uint8_t *privkey);
void crypto_ecc256_make_key_pair(uint8_t *pubkey, uint8_t *privkey);
void crypto_ecc256_shared_secret(const uint8_t *pubkey, const uint8_t *privkey,
				 uint8_t *shared_secret);

void crypto_aes256_init(uint8_t *key, uint8_t *nonce);
void crypto_aes256_reset_iv(uint8_t *nonce);

// buf length must be multiple of 16 bytes
void crypto_aes256_decrypt(uint8_t *buf, int lenth);
void crypto_aes256_encrypt(uint8_t *buf, int lenth);

void crypto_derive_device_keys(uint8_t *salt, uint8_t salt_size);

#endif
