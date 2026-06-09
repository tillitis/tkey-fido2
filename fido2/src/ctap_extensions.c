// SPDX-FileCopyrightText: 2019 SoloKeys Developers
// SPDX-FileCopyrightText: 2026 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: Apache-2.0 OR MIT

#include <stdint.h>

#include "crypto.h"
#include "ctap_client_pin.h"
#include "ctap_errors.h"
#include "ctap_parse.h"
#include "log.h"

extern struct _getAssertionState getAssertionState;

static CtapStatus ctap_extensions_parse_hmac_secret(CborValue *val,
						    CTAP_hmac_secret *hs);

CtapStatus ctap_extensions_encode_output(CTAP_extensions *ext,
					 uint8_t *ext_encoder_buf,
					 size_t *ext_encoder_buf_size)
{
	CborEncoder extensions;
	CborError cbor_ret;
	uint8_t extensions_used = 0;
	uint8_t hmac_secret_output_is_valid = 0;
	uint8_t hmac_secret_requested_is_valid = 0;
	uint8_t cred_protect_is_valid = 0;
	uint8_t hmac_secret_output[64];
	uint8_t shared_secret[32];
	uint8_t credRandom[32];
	uint8_t saltEnc[64];

	if (ext->hmac_secret_present == EXT_HMAC_SECRET_PARSED) {
		printf1(TAG_CTAP, "Processing hmac-secret..\n");
		memmove(saltEnc, ext->hmac_secret.saltEnc, sizeof(saltEnc));

		// In pin protocol 1 there only exists one shared secret.
		ctap_client_pin_decapsulate(
		    (uint8_t *)&ext->hmac_secret.keyAgreement.pubkey, 1,
		    shared_secret, shared_secret);

		if (ctap_client_pin_verify(shared_secret, saltEnc,
					   ext->hmac_secret.saltLen,
					   ext->hmac_secret.saltAuth, 1) < 0) {
			printf1(TAG_CTAP, "saltAuth is invalid\n");
			return (CtapStatus){CTAP2_ERR_PIN_AUTH_INVALID};
		}
		printf1(TAG_CTAP, "saltAuth is valid\n");

		const uint8_t *hmac_key = crypto_get_key_hmac();

		// Generate credRandom
		crypto_sha256_hmac_init(hmac_key, CRYPTO_KEY_LEN);
		crypto_sha256_update(
		    (uint8_t *)&ext->hmac_secret.credential->id,
		    sizeof(CredentialId));
		crypto_sha256_update(&getAssertionState.user_verified, 1);
		crypto_sha256_hmac_final(hmac_key, CRYPTO_KEY_LEN, credRandom);

		// Decrypt saltEnc
		crypto_aes256_init(shared_secret, NULL);
		crypto_aes256_decrypt(saltEnc, ext->hmac_secret.saltLen);

		// Generate outputs
		crypto_sha256_hmac_init(credRandom, 32);
		crypto_sha256_update(saltEnc, 32);
		crypto_sha256_hmac_final(credRandom, 32, hmac_secret_output);

		if (ext->hmac_secret.saltLen == 64) {
			crypto_sha256_hmac_init(credRandom, 32);
			crypto_sha256_update(saltEnc + 32, 32);
			crypto_sha256_hmac_final(credRandom, 32,
						 hmac_secret_output + 32);
		}

		// Encrypt for final output
		crypto_aes256_init(shared_secret, NULL);
		crypto_aes256_encrypt(hmac_secret_output,
				      ext->hmac_secret.saltLen);

		extensions_used += 1;
		hmac_secret_output_is_valid = 1;
	} else if (ext->hmac_secret_present == EXT_HMAC_SECRET_REQUESTED) {
		extensions_used += 1;
		hmac_secret_requested_is_valid = 1;
	}
	if (ext->cred_protect != EXT_CRED_PROTECT_INVALID) {
		if (ext->cred_protect == EXT_CRED_PROTECT_OPTIONAL ||
		    ext->cred_protect ==
			EXT_CRED_PROTECT_OPTIONAL_WITH_CREDID ||
		    ext->cred_protect == EXT_CRED_PROTECT_REQUIRED) {
			extensions_used += 1;
			cred_protect_is_valid = 1;
		}
	}

	if (extensions_used > 0) {

		// output
		cbor_encoder_init(&extensions, ext_encoder_buf,
				  *ext_encoder_buf_size, 0);
		{
			CborEncoder extension_output_map;
			cbor_ret = cbor_encoder_create_map(
			    &extensions, &extension_output_map,
			    extensions_used);
			cbor_check_ret(cbor_ret);
			if (hmac_secret_output_is_valid) {
				{
					cbor_ret = cbor_encode_text_stringz(
					    &extension_output_map,
					    "hmac-secret");
					cbor_check_ret(cbor_ret);

					cbor_ret = cbor_encode_byte_string(
					    &extension_output_map,
					    hmac_secret_output,
					    ext->hmac_secret.saltLen);
					cbor_check_ret(cbor_ret);
				}
			}
			if (cred_protect_is_valid) {
				{
					cbor_ret = cbor_encode_text_stringz(
					    &extension_output_map,
					    "credProtect");
					cbor_check_ret(cbor_ret);

					cbor_ret = cbor_encode_int(
					    &extension_output_map,
					    ext->cred_protect);
					cbor_check_ret(cbor_ret);
				}
			}
			if (hmac_secret_requested_is_valid) {
				{
					cbor_ret = cbor_encode_text_stringz(
					    &extension_output_map,
					    "hmac-secret");
					cbor_check_ret(cbor_ret);

					cbor_ret = cbor_encode_boolean(
					    &extension_output_map, 1);
					cbor_check_ret(cbor_ret);
				}
			}

			cbor_ret = cbor_encoder_close_container(
			    &extensions, &extension_output_map);
			cbor_check_ret(cbor_ret);
		}
		*ext_encoder_buf_size =
		    cbor_encoder_get_buffer_size(&extensions, ext_encoder_buf);

	} else {
		*ext_encoder_buf_size = 0;
	}

	return (CtapStatus){CTAP2_OK};
}

CtapStatus ctap_extensions_parse_input(CborValue *val, CTAP_extensions *ext,
				       ReqType request)
{
	CborValue map;
	size_t sz, map_length;
	char key[16];
	CborError cbor_ret;
	CtapStatus ctap_ret;
	unsigned int i;
	bool b;

	assert((REQ_TYPE_MC == request) || (REQ_TYPE_GA == request));

	if (cbor_value_get_type(val) != CborMapType) {
		printf2(TAG_ERR, "Error, expecting cbor map\n");
		return (CtapStatus){CTAP2_ERR_INVALID_CBOR};
	}

	cbor_ret = cbor_value_enter_container(val, &map);
	cbor_check_ret(cbor_ret);

	cbor_ret = cbor_value_get_map_length(val, &map_length);
	cbor_check_ret(cbor_ret);

	for (i = 0; i < map_length; i++) {
		if (cbor_value_get_type(&map) != CborTextStringType) {
			printf2(TAG_ERR,
				"Error, expecting text string type for options "
				"map key, got %s\n",
				cbor_value_get_type_string(&map));
			return (CtapStatus){CTAP2_ERR_INVALID_CBOR};
		}
		sz = sizeof(key);
		cbor_ret = cbor_value_copy_text_string(&map, key, &sz, NULL);

		if (cbor_ret == CborErrorOutOfMemory) {
			printf2(TAG_ERR,
				"Error, rp map key is too large. Ignoring.\n");
			cbor_check_ret(cbor_value_advance(&map));
			cbor_check_ret(cbor_value_advance(&map));
			continue;
		}
		cbor_check_ret(cbor_ret);
		key[sizeof(key) - 1] = 0;

		cbor_ret = cbor_value_advance(&map);
		cbor_check_ret(cbor_ret);

		if ((strncmp(key, "hmac-secret", 11) == 0) &&
		    (key[11] == '\0')) {
			if (REQ_TYPE_MC == request) {
				if (cbor_value_get_type(&map) !=
				    CborBooleanType) {
					return (CtapStatus){
					    CTAP2_ERR_INVALID_CBOR};
				}
				cbor_ret = cbor_value_get_boolean(&map, &b);
				cbor_check_ret(cbor_ret);
				if (b) {
					ext->hmac_secret_present =
					    EXT_HMAC_SECRET_REQUESTED;
					printf1(
					    TAG_CTAP,
					    "Set hmac_secret_present to %d\n",
					    b);
				}
			} else if (REQ_TYPE_GA == request) {
				if (cbor_value_get_type(&map) != CborMapType) {
					return (CtapStatus){
					    CTAP2_ERR_INVALID_CBOR};
				}
				ctap_ret = ctap_extensions_parse_hmac_secret(
				    &map, &ext->hmac_secret);
				ctap_check_retr(ctap_ret);
				ext->hmac_secret_present =
				    EXT_HMAC_SECRET_PARSED;
				printf1(TAG_CTAP,
					"parsed hmac_secret request\n");
			}
		} else if ((strncmp(key, "credProtect", 11) == 0) &&
			   (key[11] == '\0')) {
			if (REQ_TYPE_MC != request) {
				return (CtapStatus){CTAP2_ERR_INVALID_CBOR};
			}
			if (cbor_value_get_type(&map) != CborIntegerType) {
				return (CtapStatus){CTAP2_ERR_INVALID_CBOR};
			}

			int value;
			cbor_ret = cbor_value_get_int(&map, &value);
			cbor_check_ret(cbor_ret);

			if ((value >= 1) && (value <= 3)) {
				ext->cred_protect = (uint8_t)value;
			} else {
				printf1(
				    TAG_RED,
				    "Warning: invalid credProtect value %d\n",
				    value);
				return (CtapStatus){
				    CTAP1_ERR_INVALID_PARAMETER};
			}
		}

		cbor_ret = cbor_value_advance(&map);
		cbor_check_ret(cbor_ret);
	}
	return (CtapStatus){CTAP2_OK};
}

static CtapStatus ctap_extensions_parse_hmac_secret(CborValue *val,
						    CTAP_hmac_secret *hs)
{
	size_t map_length;
	size_t salt_len;
	uint8_t parsed_count = 0;
	int key;
	CborError cbor_ret;
	CtapStatus ctap_ret;
	unsigned int i;
	CborValue map;

	if (cbor_value_get_type(val) != CborMapType) {
		printf2(TAG_ERR, "Error, expecting cbor map\n");
		return (CtapStatus){CTAP2_ERR_INVALID_CBOR};
	}

	cbor_ret = cbor_value_enter_container(val, &map);
	cbor_check_ret(cbor_ret);

	cbor_ret = cbor_value_get_map_length(val, &map_length);
	cbor_check_ret(cbor_ret);

	for (i = 0; i < map_length; i++) {
		if (cbor_value_get_type(&map) != CborIntegerType) {
			printf2(TAG_ERR,
				"Error, expecting CborIntegerTypefor "
				"hmac-secret map key, got %s\n",
				cbor_value_get_type_string(&map));
			return (CtapStatus){CTAP2_ERR_INVALID_CBOR};
		}
		cbor_ret = cbor_value_get_int(&map, &key);
		cbor_check_ret(cbor_ret);

		cbor_ret = cbor_value_advance(&map);
		cbor_check_ret(cbor_ret);

		switch (key) {

		case EXT_HMAC_SECRET_COSE_KEY:
			ctap_ret = cose_key_parse(&map, &hs->keyAgreement);
			ctap_check_retr(ctap_ret);
			parsed_count++;
			break;

		case EXT_HMAC_SECRET_SALT_ENC:
			salt_len = 64;
			cbor_ret = cbor_value_copy_byte_string(
			    &map, hs->saltEnc, &salt_len, NULL);
			if ((salt_len != 32 && salt_len != 64) ||
			    cbor_ret == CborErrorOutOfMemory) {
				return (CtapStatus){CTAP1_ERR_INVALID_LENGTH};
			}
			cbor_check_ret(cbor_ret);
			hs->saltLen = (uint8_t)salt_len;
			parsed_count++;
			break;

		case EXT_HMAC_SECRET_SALT_AUTH:
			salt_len = 32;
			cbor_ret = cbor_value_copy_byte_string(
			    &map, hs->saltAuth, &salt_len, NULL);
			cbor_check_ret(cbor_ret);
			parsed_count++;
			break;
		}

		cbor_ret = cbor_value_advance(&map);
		cbor_check_ret(cbor_ret);
	}

	if (parsed_count != 3) {
		printf2(TAG_ERR,
			"Error, ctap_extensions_parse_hmac_secret() missing "
			"parameter. Got %d.\n",
			parsed_count);
		return (CtapStatus){CTAP2_ERR_MISSING_PARAMETER};
	}

	return (CtapStatus){CTAP2_OK};
}
