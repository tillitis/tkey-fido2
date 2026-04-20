#include <stdint.h>

#include "crypto.h"
#include "ctap.h"
#include "ctap_errors.h"
#include "ctap_parse.h"
#include "log.h"

extern uint8_t KEY_AGREEMENT_PRIV[32];
extern struct _getAssertionState getAssertionState;

int ctap_make_extensions(CTAP_extensions *ext, uint8_t *ext_encoder_buf,
			 unsigned int *ext_encoder_buf_size)
{
	CborEncoder extensions;
	int ret;
	uint8_t extensions_used = 0;
	uint8_t hmac_secret_output_is_valid = 0;
	uint8_t hmac_secret_requested_is_valid = 0;
	uint8_t cred_protect_is_valid = 0;
	uint8_t hmac_secret_output[64];
	uint8_t shared_secret[32];
	uint8_t hmac[32];
	uint8_t credRandom[32];
	uint8_t saltEnc[64];

	if (ext->hmac_secret_present == EXT_HMAC_SECRET_PARSED) {
		printf1(TAG_CTAP, "Processing hmac-secret..\r\n");
		memmove(saltEnc, ext->hmac_secret.saltEnc, sizeof(saltEnc));

		crypto_ecc256_shared_secret(
		    (uint8_t *)&ext->hmac_secret.keyAgreement.pubkey,
		    KEY_AGREEMENT_PRIV, shared_secret);
		crypto_sha256_init();
		crypto_sha256_update(shared_secret, 32);
		crypto_sha256_final(shared_secret);

		crypto_sha256_hmac_init(shared_secret, 32);
		crypto_sha256_update(saltEnc, ext->hmac_secret.saltLen);
		crypto_sha256_hmac_final(shared_secret, 32, hmac);

		if (memcmp(ext->hmac_secret.saltAuth, hmac, 16) == 0) {
			printf1(TAG_CTAP, "saltAuth is valid\r\n");
		} else {
			printf1(TAG_CTAP, "saltAuth is invalid\r\n");
			return CTAP2_ERR_EXTENSION_FIRST;
		}

		uint8_t key_len = 0;
		const uint8_t *hmac_key = crypto_get_key_hmac(&key_len);

		// Generate credRandom
		crypto_sha256_hmac_init(hmac_key, key_len);
		crypto_sha256_update(
		    (uint8_t *)&ext->hmac_secret.credential->id,
		    sizeof(CredentialId));
		crypto_sha256_update(&getAssertionState.user_verified, 1);
		crypto_sha256_hmac_final(hmac_key, key_len, credRandom);

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
			ret = cbor_encoder_create_map(&extensions,
						      &extension_output_map,
						      extensions_used);
			check_ret(ret);
			if (hmac_secret_output_is_valid) {
				{
					ret = cbor_encode_text_stringz(
					    &extension_output_map,
					    "hmac-secret");
					check_ret(ret);

					ret = cbor_encode_byte_string(
					    &extension_output_map,
					    hmac_secret_output,
					    ext->hmac_secret.saltLen);
					check_ret(ret);
				}
			}
			if (cred_protect_is_valid) {
				{
					ret = cbor_encode_text_stringz(
					    &extension_output_map,
					    "credProtect");
					check_ret(ret);

					ret = cbor_encode_int(
					    &extension_output_map,
					    ext->cred_protect);
					check_ret(ret);
				}
			}
			if (hmac_secret_requested_is_valid) {
				{
					ret = cbor_encode_text_stringz(
					    &extension_output_map,
					    "hmac-secret");
					check_ret(ret);

					ret = cbor_encode_boolean(
					    &extension_output_map, 1);
					check_ret(ret);
				}
			}

			ret = cbor_encoder_close_container(
			    &extensions, &extension_output_map);
			check_ret(ret);
		}
		*ext_encoder_buf_size =
		    cbor_encoder_get_buffer_size(&extensions, ext_encoder_buf);

	} else {
		*ext_encoder_buf_size = 0;
	}

	return 0;
}

uint8_t ctap_parse_extensions(CborValue *val, CTAP_extensions *ext)
{
	CborValue map;
	size_t sz, map_length;
	char key[16];
	int ret;
	unsigned int i;
	bool b;

	if (cbor_value_get_type(val) != CborMapType) {
		printf2(TAG_ERR, "error, wrong type\n");
		return CTAP2_ERR_INVALID_CBOR;
	}

	ret = cbor_value_enter_container(val, &map);
	check_ret(ret);

	ret = cbor_value_get_map_length(val, &map_length);
	check_ret(ret);

	for (i = 0; i < map_length; i++) {
		if (cbor_value_get_type(&map) != CborTextStringType) {
			printf2(TAG_ERR,
				"Error, expecting text string type for options "
				"map key, got %s\n",
				cbor_value_get_type_string(&map));
			return CTAP2_ERR_INVALID_CBOR;
		}
		sz = sizeof(key);
		ret = cbor_value_copy_text_string(&map, key, &sz, NULL);

		if (ret == CborErrorOutOfMemory) {
			printf2(TAG_ERR,
				"Error, rp map key is too large. Ignoring.\n");
			check_ret(cbor_value_advance(&map));
			check_ret(cbor_value_advance(&map));
			continue;
		}
		check_ret(ret);
		key[sizeof(key) - 1] = 0;

		ret = cbor_value_advance(&map);
		check_ret(ret);

		if (strncmp(key, "hmac-secret", 11) == 0) {
			if (cbor_value_get_type(&map) == CborBooleanType) {
				ret = cbor_value_get_boolean(&map, &b);
				check_ret(ret);
				if (b)
					ext->hmac_secret_present =
					    EXT_HMAC_SECRET_REQUESTED;
				printf1(TAG_CTAP,
					"set hmac_secret_present to %d\r\n", b);
			} else if (cbor_value_get_type(&map) == CborMapType) {
				ret = ctap_parse_hmac_secret(&map,
							     &ext->hmac_secret);
				check_retr(ret);
				ext->hmac_secret_present =
				    EXT_HMAC_SECRET_PARSED;
				printf1(TAG_CTAP,
					"parsed hmac_secret request\r\n");
			} else {
				printf1(TAG_RED,
					"warning: hmac_secret request ignored "
					"for being wrong type\r\n");
			}
		} else if (strncmp(key, "credProtect", 11) == 0) {
			if (cbor_value_get_type(&map) == CborIntegerType) {
				int value;
				ret = cbor_value_get_int(&map, &value);
				check_ret(ret);

				if (value >= 1 && value <= 3) {
					ext->cred_protect = (uint8_t)value;
				} else {
					printf1(TAG_RED,
						"warning: invalid credProtect "
						"value %d\r\n",
						value);
				}
			} else {
				printf1(TAG_RED,
					"warning: credProtect request ignored "
					"for being wrong type\r\n");
			}
		}

		ret = cbor_value_advance(&map);
		check_ret(ret);
	}
	return 0;
}

uint8_t ctap_parse_hmac_secret(CborValue *val, CTAP_hmac_secret *hs)
{
	size_t map_length;
	size_t salt_len;
	uint8_t parsed_count = 0;
	int key;
	int ret;
	unsigned int i;
	CborValue map;

	if (cbor_value_get_type(val) != CborMapType) {
		printf2(TAG_ERR, "error, wrong type\n");
		return CTAP2_ERR_INVALID_CBOR;
	}

	ret = cbor_value_enter_container(val, &map);
	check_ret(ret);

	ret = cbor_value_get_map_length(val, &map_length);
	check_ret(ret);

	for (i = 0; i < map_length; i++) {
		if (cbor_value_get_type(&map) != CborIntegerType) {
			printf2(TAG_ERR,
				"Error, expecting CborIntegerTypefor "
				"hmac-secret map key, got %s\n",
				cbor_value_get_type_string(&map));
			return CTAP2_ERR_INVALID_CBOR;
		}
		ret = cbor_value_get_int(&map, &key);
		check_ret(ret);

		ret = cbor_value_advance(&map);
		check_ret(ret);

		switch (key) {
		case EXT_HMAC_SECRET_COSE_KEY:
			ret = parse_cose_key(&map, &hs->keyAgreement);
			check_retr(ret);
			parsed_count++;
			break;
		case EXT_HMAC_SECRET_SALT_ENC:
			salt_len = 64;
			ret = cbor_value_copy_byte_string(&map, hs->saltEnc,
							  &salt_len, NULL);
			if ((salt_len != 32 && salt_len != 64) ||
			    ret == CborErrorOutOfMemory) {
				return CTAP1_ERR_INVALID_LENGTH;
			}
			check_ret(ret);
			hs->saltLen = salt_len;
			parsed_count++;
			break;
		case EXT_HMAC_SECRET_SALT_AUTH:
			salt_len = 32;
			ret = cbor_value_copy_byte_string(&map, hs->saltAuth,
							  &salt_len, NULL);
			check_ret(ret);
			parsed_count++;
			break;
		}

		ret = cbor_value_advance(&map);
		check_ret(ret);
	}

	if (parsed_count != 3) {
		printf2(
		    TAG_ERR,
		    "ctap_parse_hmac_secret missing parameter.  Got %d.\r\n",
		    parsed_count);
		return CTAP2_ERR_MISSING_PARAMETER;
	}

	return 0;
}
