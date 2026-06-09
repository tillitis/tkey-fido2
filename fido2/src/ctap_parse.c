// SPDX-FileCopyrightText: 2019 SoloKeys Developers
// SPDX-FileCopyrightText: 2026 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: Apache-2.0 OR MIT

#include <stdint.h>

#include "cbor.h"
#include "cose_key.h"
#include "ctap_errors.h"
#include "ctap_parse.h"
#include "log.h"
#include "u2f.h"
#include "util.h"

extern struct _getAssertionState getAssertionState;

void _cbor_check_ret(CborError ret, int line, const char *filename)
{
	if (ret != CborNoError) {
		printf1(TAG_ERR, "CborError: 0x%x: %s: %d: %s\n", ret, filename,
			line, cbor_error_string(ret));
		/*exit(1);*/
	}
}

void _ctap_check_ret(CtapStatus ret, int line, const char *filename)
{
	if (ret.value != CTAP2_OK) {
		printf1(TAG_ERR, "CTAP Error: 0x%x: %s: %d: %s\n", ret.value,
			filename, line, ctap_error_string(ret));
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
	case CborInvalidType:
		return "CborInvalidType";
		break;
	default:
		return "Unknown type";
	}
}

CtapStatus
ctap_parse_pubkey_credential_descriptor(CborValue *arr,
					CTAP_credentialDescriptor *cred)
{
	CborError cbor_ret;
	size_t buflen;
	char keytype[12];
	CborValue val;
	cred->type = 0;

	if (cbor_value_get_type(arr) != CborMapType) {
		printf2(TAG_ERR, "Error, expecting cbor map\n");
		return (CtapStatus){CTAP2_ERR_INVALID_CBOR};
	}

	cbor_ret = cbor_value_map_find_value(arr, "id", &val);
	cbor_check_ret(cbor_ret);

	if (cbor_value_get_type(&val) != CborByteStringType) {
		printf2(TAG_ERR, "Error, No valid ID field (%s)\n",
			cbor_value_get_type_string(&val));
		return (CtapStatus){CTAP2_ERR_MISSING_PARAMETER};
	}

	buflen = sizeof(CredentialId);
	cbor_ret = cbor_value_copy_byte_string(
	    &val, (uint8_t *)&cred->credential.id, &buflen, NULL);

	if (buflen == U2F_KEY_HANDLE_SIZE) {
		printf2(TAG_PARSE, "CTAP1 credential\n");
		cred->type = PUB_KEY_CRED_CTAP1;
	}
	cbor_check_ret(cbor_ret);

	cbor_ret = cbor_value_map_find_value(arr, "type", &val);
	cbor_check_ret(cbor_ret);

	if (cbor_value_get_type(&val) != CborTextStringType) {
		printf2(TAG_ERR, "Error, No valid type field\n");
		return (CtapStatus){CTAP2_ERR_MISSING_PARAMETER};
	}

	buflen = sizeof(keytype);
	cbor_ret = cbor_value_copy_text_string(&val, keytype, &buflen, NULL);
	if (cbor_ret == CborErrorOutOfMemory) {
		cred->type = PUB_KEY_CRED_UNKNOWN;
	} else {
		cbor_check_ret(cbor_ret);
	}

	if ((strncmp(keytype, "public-key", 10) == 0) &&
	    (keytype[10] == '\0')) {
		if (0 == cred->type) {
			cred->type = PUB_KEY_CRED_PUB_KEY;
		}
	} else {
		cred->type = PUB_KEY_CRED_UNKNOWN;
		printf1(TAG_RED, "Unknown type: %s\n", keytype);
	}

	return (CtapStatus){CTAP2_OK};
}

CtapStatus ctap_parse_fixed_length_byte_string(CborValue *map, uint8_t *dst,
					       unsigned int len)
{
	size_t sz;
	CborError cbor_ret;
	if (cbor_value_get_type(map) != CborByteStringType) {
		printf2(TAG_ERR, "Error, expecting byte string\n");
		return (CtapStatus){CTAP2_ERR_INVALID_CBOR};
	}
	sz = len;
	cbor_ret = cbor_value_copy_byte_string(map, dst, &sz, NULL);
	cbor_check_ret(cbor_ret);
	if (sz != len) {
		printf2(TAG_ERR,
			"Error, byte string is different length (%d vs "
			"%d)\n",
			len, sz);
		return (CtapStatus){CTAP1_ERR_INVALID_LENGTH};
	}

	return (CtapStatus){CTAP2_OK};
}

CtapStatus ctap_parse_options(CborValue *val, uint8_t *rk, uint8_t *uv,
			      uint8_t *up)
{
	size_t sz, map_length;
	char key[8];
	CborError cbor_ret;
	unsigned int i;
	_Bool b;
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
			printf2(TAG_ERR, "Error, rp map key is too large\n");
			return (CtapStatus){CTAP2_ERR_LIMIT_EXCEEDED};
		}
		cbor_check_ret(cbor_ret);
		key[sizeof(key) - 1] = 0;

		cbor_ret = cbor_value_advance(&map);
		cbor_check_ret(cbor_ret);

		if (cbor_value_get_type(&map) != CborBooleanType) {
			printf2(TAG_ERR, "Error, expecting bool type for "
					 "option map value\n");
			return (CtapStatus){CTAP2_ERR_INVALID_CBOR};
		}

		if ((strncmp(key, "rk", 2) == 0) && (key[2] == '\0')) {
			cbor_ret = cbor_value_get_boolean(&map, &b);
			cbor_check_ret(cbor_ret);
			printf1(TAG_GA, "rk: %d\n", b);
			*rk = b;
		} else if ((strncmp(key, "uv", 2) == 0) && (key[2] == '\0')) {
			cbor_ret = cbor_value_get_boolean(&map, &b);
			cbor_check_ret(cbor_ret);
			printf1(TAG_GA, "uv: %d\n", b);
			*uv = b;
		} else if ((strncmp(key, "up", 2) == 0) && (key[2] == '\0')) {
			cbor_ret = cbor_value_get_boolean(&map, &b);
			cbor_check_ret(cbor_ret);
			printf1(TAG_GA, "up: %d\n", b);
			*up = b;
		} else {
			printf2(TAG_PARSE, "ignoring option specified %s\n",
				key);
		}
		cbor_ret = cbor_value_advance(&map);
		cbor_check_ret(cbor_ret);
	}

	return (CtapStatus){CTAP2_OK};
}

CtapStatus ctap_parse_rp_id(struct rpId *rp, CborValue *val)
{
	CborError cbor_ret;
	size_t sz = DOMAIN_NAME_MAX_SIZE;
	if (cbor_value_get_type(val) != CborTextStringType) {
		return (CtapStatus){CTAP2_ERR_INVALID_CBOR};
	}
	cbor_ret = cbor_value_copy_text_string(val, (char *)rp->id, &sz, NULL);
	if (cbor_ret == CborErrorOutOfMemory) {
		printf2(TAG_ERR, "Error, RP_ID is too large\n");
		return (CtapStatus){CTAP2_ERR_LIMIT_EXCEEDED};
	}
	cbor_check_ret(cbor_ret);
	rp->id[DOMAIN_NAME_MAX_SIZE] = 0; // Extra byte defined in struct.
	rp->size = sz;

	return (CtapStatus){CTAP2_OK};
}

CtapStatus ctap_parse_user_entity(CTAP_userEntity *user, CborValue *val)
{
	size_t sz;
	size_t map_length;
	uint8_t key[24];
	CborError cbor_ret;
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
		if (cbor_value_get_type(&map) != CborTextStringType) {
			printf2(TAG_ERR,
				"Error, expecting text string type for user "
				"map key, got %s\n",
				cbor_value_get_type_string(&map));
			return (CtapStatus){CTAP2_ERR_INVALID_CBOR};
		}

		sz = sizeof(key);
		cbor_ret =
		    cbor_value_copy_text_string(&map, (char *)key, &sz, NULL);

		if (cbor_ret == CborErrorOutOfMemory) {
			printf2(TAG_ERR, "Error, rp map key is too large\n");
			return (CtapStatus){CTAP2_ERR_LIMIT_EXCEEDED};
		}

		cbor_check_ret(cbor_ret);
		key[sizeof(key) - 1] = 0;

		cbor_ret = cbor_value_advance(&map);
		cbor_check_ret(cbor_ret);

		if (strcmp((const char *)key, "id") == 0) {

			if (cbor_value_get_type(&map) != CborByteStringType) {
				printf2(TAG_ERR, "Error, expecting byte string "
						 "type for rp map value\n");
				return (CtapStatus){CTAP2_ERR_INVALID_CBOR};
			}

			sz = USER_ID_MAX_SIZE;
			cbor_ret = cbor_value_copy_byte_string(&map, user->id,
							       &sz, NULL);
			if (cbor_ret == CborErrorOutOfMemory) {
				printf2(TAG_ERR,
					"Error, USER_ID is too large\n");
				return (CtapStatus){CTAP2_ERR_LIMIT_EXCEEDED};
			}
			cbor_check_ret(cbor_ret);
			if (sz > UINT8_MAX) {
				return (CtapStatus){CTAP2_ERR_INVALID_CBOR};
			}
			user->id_size = (uint8_t)sz;

		} else if (strcmp((const char *)key, "name") == 0) {
			if (cbor_value_get_type(&map) != CborTextStringType) {
				printf2(TAG_ERR, "Error, expecting text string "
						 "type for user.name value\n");
				return (CtapStatus){CTAP2_ERR_INVALID_CBOR};
			}
			sz = USER_NAME_LIMIT;
			cbor_ret = cbor_value_copy_text_string(
			    &map, (char *)user->name, &sz, NULL);
			if (cbor_ret !=
			    CborErrorOutOfMemory) { // Just truncate the
						    // name it's okay
				cbor_check_ret(cbor_ret);
			}
			user->name[USER_NAME_LIMIT - 1] = 0;

		} else if (strcmp((const char *)key, "displayName") == 0) {
			if (cbor_value_get_type(&map) != CborTextStringType) {
				printf2(TAG_ERR,
					"Error, expecting text string type for "
					"user.displayName value\n");
				return (CtapStatus){CTAP2_ERR_INVALID_CBOR};
			}
			sz = DISPLAY_NAME_LIMIT;
			cbor_ret = cbor_value_copy_text_string(
			    &map, (char *)user->displayName, &sz, NULL);
			if (cbor_ret !=
			    CborErrorOutOfMemory) { // Just truncate the
						    // name it's okay
				cbor_check_ret(cbor_ret);
			}
			user->displayName[DISPLAY_NAME_LIMIT - 1] = 0;

		} else if (strcmp((const char *)key, "icon") == 0) {
			// Icon is deprecated, don't store it.
			// Still need to parse it and return error if it is
			// malformed.

			if (cbor_value_get_type(&map) != CborTextStringType) {
				printf2(TAG_ERR, "Error, expecting text string "
						 "type for user.icon value\n");
				return (CtapStatus){CTAP2_ERR_INVALID_CBOR};
			}

		} else {
			printf1(TAG_PARSE, "ignoring key %s for user map\n",
				key);
		}

		cbor_ret = cbor_value_advance(&map);
		cbor_check_ret(cbor_ret);
	}

	return (CtapStatus){CTAP2_OK};
}
