#include <stdint.h>

#include "cbor.h"
#include "cose_key.h"
#include "crypto.h"
#include "ctap_parse.h"
#include "log.h"

int ctap_add_cose_key(CborEncoder *cose_key, uint8_t *x, uint8_t *y,
		      uint8_t credtype, int32_t algtype)
{
	int ret;
	CborEncoder map;

	ret = cbor_encoder_create_map(cose_key, &map,
				      algtype != COSE_ALG_EDDSA ? 5 : 4);
	check_ret(ret);

	{
		ret = cbor_encode_int(&map, COSE_KEY_LABEL_KTY);
		check_ret(ret);
		ret = cbor_encode_int(&map, algtype != COSE_ALG_EDDSA
						? COSE_KEY_KTY_EC2
						: COSE_KEY_KTY_OKP);
		check_ret(ret);
	}

	{
		ret = cbor_encode_int(&map, COSE_KEY_LABEL_ALG);
		check_ret(ret);
		ret = cbor_encode_int(&map, algtype);
		check_ret(ret);
	}

	{
		ret = cbor_encode_int(&map, COSE_KEY_LABEL_CRV);
		check_ret(ret);
		ret = cbor_encode_int(&map, algtype != COSE_ALG_EDDSA
						? COSE_KEY_CRV_P256
						: COSE_KEY_CRV_ED25519);
		check_ret(ret);
	}

	{
		ret = cbor_encode_int(&map, COSE_KEY_LABEL_X);
		check_ret(ret);
		ret = cbor_encode_byte_string(&map, x, 32);
		check_ret(ret);
	}

	if (algtype != COSE_ALG_EDDSA) {
		ret = cbor_encode_int(&map, COSE_KEY_LABEL_Y);
		check_ret(ret);
		ret = cbor_encode_byte_string(&map, y, 32);
		check_ret(ret);
	}

	ret = cbor_encoder_close_container(cose_key, &map);
	check_ret(ret);

	return 0;
}

int ctap_generate_cose_key(CborEncoder *cose_key, uint8_t *hmac_input, int len,
			   uint8_t credtype, int32_t algtype)
{
	uint8_t x[32], y[32];

	if (credtype != PUB_KEY_CRED_PUB_KEY) {
		printf2(TAG_ERR,
			"Error, pubkey credential type not supported\n");
		return -1;
	}
	switch (algtype) {
	case COSE_ALG_ES256:
		crypto_ecc256_derive_public_key(hmac_input, len, x, y);
		break;
	case COSE_ALG_EDDSA:
		fido2_crypto_ed25519_derive_public_key(hmac_input, len, x);
		break;
	default:
		printf2(TAG_ERR, "Error, COSE alg %d not supported\n", algtype);
		return -1;
	}
	int ret = ctap_add_cose_key(cose_key, x, y, credtype, algtype);
	check_ret(ret);
	return 0;
}

uint8_t parse_cose_key(CborValue *it, COSE_key *cose)
{
	CborValue map;
	size_t map_length;
	int ret, key;
	unsigned int i;
	int xkey = 0, ykey = 0;
	cose->kty = 0;
	cose->crv = 0;

	CborType type = cbor_value_get_type(it);
	if (type != CborMapType) {
		printf2(TAG_ERR, "Error, expecting cbor map\n");
		return CTAP2_ERR_INVALID_CBOR;
	}

	ret = cbor_value_enter_container(it, &map);
	check_ret(ret);

	ret = cbor_value_get_map_length(it, &map_length);
	check_ret(ret);

	printf1(TAG_PARSE, "cose key has %d elements\n", map_length);

	for (i = 0; i < map_length; i++) {
		if (cbor_value_get_type(&map) != CborIntegerType) {
			printf2(TAG_ERR, "Error, expecting int for map key\n");
			return CTAP2_ERR_INVALID_CBOR;
		}

		ret = cbor_value_get_int_checked(&map, &key);
		check_ret(ret);

		ret = cbor_value_advance(&map);
		check_ret(ret);

		switch (key) {
		case COSE_KEY_LABEL_KTY:
			printf1(TAG_PARSE, "COSE_KEY_LABEL_KTY\n");
			if (cbor_value_get_type(&map) == CborIntegerType) {
				ret = cbor_value_get_int_checked(&map,
								 &cose->kty);
				check_ret(ret);
			} else {
				return CTAP2_ERR_INVALID_CBOR;
			}
			break;
		case COSE_KEY_LABEL_ALG:
			printf1(TAG_PARSE, "COSE_KEY_LABEL_ALG\n");
			break;
		case COSE_KEY_LABEL_CRV:
			printf1(TAG_PARSE, "COSE_KEY_LABEL_CRV\n");
			if (cbor_value_get_type(&map) == CborIntegerType) {
				ret = cbor_value_get_int_checked(&map,
								 &cose->crv);
				check_ret(ret);
			} else {
				return CTAP2_ERR_INVALID_CBOR;
			}
			break;
		case COSE_KEY_LABEL_X:
			printf1(TAG_PARSE, "COSE_KEY_LABEL_X\n");
			ret = parse_fixed_byte_string(&map, cose->pubkey.x, 32);
			check_retr(ret);
			xkey = 1;

			break;
		case COSE_KEY_LABEL_Y:
			printf1(TAG_PARSE, "COSE_KEY_LABEL_Y\n");
			ret = parse_fixed_byte_string(&map, cose->pubkey.y, 32);
			check_retr(ret);
			ykey = 1;

			break;
		default:
			printf1(TAG_PARSE,
				"Warning, unrecognized cose key option %d\n",
				key);
		}

		ret = cbor_value_advance(&map);
		check_ret(ret);
	}
	if (xkey == 0 || ykey == 0 || cose->kty == 0 || cose->crv == 0) {
		return CTAP2_ERR_MISSING_PARAMETER;
	}
	return 0;
}
