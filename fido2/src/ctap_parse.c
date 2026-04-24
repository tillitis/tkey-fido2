// SPDX-FileCopyrightText: 2019 SoloKeys Developers
// SPDX-License-Identifier: Apache-2.0 OR MIT

#include <stdint.h>

#include "cbor.h"
#include "cose_key.h"
#include "ctap.h"
#include "ctap_errors.h"
#include "ctap_parse.h"
#include "log.h"
#include "u2f.h"
#include "util.h"

extern struct _getAssertionState getAssertionState;

void _check_ret(CborError ret, int line, const char *filename)
{
	if (ret != CborNoError) {
		printf1(TAG_ERR, "CborError: 0x%x: %s: %d: %s\n", ret, filename,
			line, cbor_error_string(ret));
		/*exit(1);*/
	}
}

const char *cbor_value_get_type_string(const CborValue *value)
{
	switch (cbor_value_get_type(value)) {
	case CborIntegerType:
		return "CborIntegerType";
		break;
	case CborByteStringType:
		return "CborByteStringType";
		break;
	case CborTextStringType:
		return "CborTextStringType";
		break;
	case CborArrayType:
		return "CborArrayType";
		break;
	case CborMapType:
		return "CborMapType";
		break;
	case CborTagType:
		return "CborTagType";
		break;
	case CborSimpleType:
		return "CborSimpleType";
		break;
	case CborBooleanType:
		return "CborBooleanType";
		break;
	case CborNullType:
		return "CborNullType";
		break;
	case CborUndefinedType:
		return "CborUndefinedType";
		break;
	case CborHalfFloatType:
		return "CborHalfFloatType";
		break;
	case CborFloatType:
		return "CborFloatType";
		break;
	case CborDoubleType:
		return "CborDoubleType";
		break;
	default:
		return "Invalid type";
	}
}

uint8_t ctap_parse_pubkey_credential_descriptor(CborValue *arr,
						CTAP_credentialDescriptor *cred)
{
	int ret;
	size_t buflen;
	char type[12];
	CborValue val;
	cred->type = 0;

	if (cbor_value_get_type(arr) != CborMapType) {
		printf2(TAG_ERR, "Error, CborMapType expected in credential\n");
		return CTAP2_ERR_INVALID_CBOR;
	}

	ret = cbor_value_map_find_value(arr, "id", &val);
	check_ret(ret);

	if (cbor_value_get_type(&val) != CborByteStringType) {
		printf2(TAG_ERR, "Error, No valid ID field (%s)\n",
			cbor_value_get_type_string(&val));
		return CTAP2_ERR_MISSING_PARAMETER;
	}

	buflen = sizeof(CredentialId);
	ret = cbor_value_copy_byte_string(&val, (uint8_t *)&cred->credential.id,
					  &buflen, NULL);

	if (buflen == U2F_KEY_HANDLE_SIZE) {
		printf2(TAG_PARSE, "CTAP1 credential\n");
		cred->type = PUB_KEY_CRED_CTAP1;
	} else if (buflen != sizeof(CredentialId)) {
		printf2(TAG_ERR, "Ignoring credential is incorrect length, "
				 "treating as custom\n");
		cred->type = PUB_KEY_CRED_CUSTOM;
		buflen = 256;
		ret = cbor_value_copy_byte_string(
		    &val, getAssertionState.customCredId, &buflen, NULL);
		getAssertionState.customCredIdSize = buflen;
	}
	check_ret(ret);

	ret = cbor_value_map_find_value(arr, "type", &val);
	check_ret(ret);

	if (cbor_value_get_type(&val) != CborTextStringType) {
		printf2(TAG_ERR, "Error, No valid type field\n");
		return CTAP2_ERR_MISSING_PARAMETER;
	}

	buflen = sizeof(type);
	ret = cbor_value_copy_text_string(&val, type, &buflen, NULL);
	if (ret == CborErrorOutOfMemory) {
		cred->type = PUB_KEY_CRED_UNKNOWN;
	} else {
		check_ret(ret);
	}

	if (strncmp(type, "public-key", 11) == 0) {
		if (0 == cred->type) {
			cred->type = PUB_KEY_CRED_PUB_KEY;
		}
	} else {
		cred->type = PUB_KEY_CRED_UNKNOWN;
		printf1(TAG_RED, "Unknown type: %s\r\n", type);
	}

	return 0;
}

uint8_t ctap_parse_fixed_length_byte_string(CborValue *map, uint8_t *dst,
					    unsigned int len)
{
	size_t sz;
	int ret;
	if (cbor_value_get_type(map) == CborByteStringType) {
		sz = len;
		ret = cbor_value_copy_byte_string(map, dst, &sz, NULL);
		check_ret(ret);
		if (sz != len) {
			printf2(TAG_ERR,
				"error byte string is different length (%d vs "
				"%d)\r\n",
				len, sz);
			return CTAP1_ERR_INVALID_LENGTH;
		}
	} else {
		printf2(TAG_ERR, "error, CborByteStringType expected\r\n");
		return CTAP2_ERR_INVALID_CBOR;
	}
	return 0;
}

uint8_t ctap_parse_options(CborValue *val, uint8_t *rk, uint8_t *uv,
			   uint8_t *up)
{
	size_t sz, map_length;
	char key[8];
	int ret;
	unsigned int i;
	_Bool b;
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
			printf2(TAG_ERR, "Error, rp map key is too large\n");
			return CTAP2_ERR_LIMIT_EXCEEDED;
		}
		check_ret(ret);
		key[sizeof(key) - 1] = 0;

		ret = cbor_value_advance(&map);
		check_ret(ret);

		if (cbor_value_get_type(&map) != CborBooleanType) {
			printf2(TAG_ERR, "Error, expecting bool type for "
					 "option map value\n");
			return CTAP2_ERR_INVALID_CBOR;
		}

		if (strncmp(key, "rk", 2) == 0) {
			ret = cbor_value_get_boolean(&map, &b);
			check_ret(ret);
			printf1(TAG_GA, "rk: %d\r\n", b);
			*rk = b;
		} else if (strncmp(key, "uv", 2) == 0) {
			ret = cbor_value_get_boolean(&map, &b);
			check_ret(ret);
			printf1(TAG_GA, "uv: %d\r\n", b);
			*uv = b;
		} else if (strncmp(key, "up", 2) == 0) {
			ret = cbor_value_get_boolean(&map, &b);
			check_ret(ret);
			printf1(TAG_GA, "up: %d\r\n", b);
			*up = b;
		} else {
			printf2(TAG_PARSE, "ignoring option specified %s\n",
				key);
		}
		ret = cbor_value_advance(&map);
		check_ret(ret);
	}
	return 0;
}

uint8_t ctap_parse_rp_id(struct rpId *rp, CborValue *val)
{
	size_t sz = DOMAIN_NAME_MAX_SIZE;
	if (cbor_value_get_type(val) != CborTextStringType) {
		return CTAP2_ERR_INVALID_CBOR;
	}
	int ret = cbor_value_copy_text_string(val, (char *)rp->id, &sz, NULL);
	if (ret == CborErrorOutOfMemory) {
		printf2(TAG_ERR, "Error, RP_ID is too large\n");
		return CTAP2_ERR_LIMIT_EXCEEDED;
	}
	check_ret(ret);
	rp->id[DOMAIN_NAME_MAX_SIZE] = 0; // Extra byte defined in struct.
	rp->size = sz;
	return 0;
}
