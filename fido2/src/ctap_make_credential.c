#include <stdint.h>

#include "crypto.h"
#include "ctap.h"
#include "ctap_errors.h"
#include "ctap_make_credential.h"
#include "ctap_parse.h"
#include "log.h"

uint8_t ctap_make_credential(CborEncoder *encoder, uint8_t *request, int length)
{
	CTAP_makeCredential MC;
	int ret;
	unsigned int i;
	uint8_t auth_data_buf[310];
	CTAP_credentialDescriptor *excl_cred =
	    (CTAP_credentialDescriptor *)auth_data_buf;
	uint8_t *sigbuf = auth_data_buf + 32;
	uint8_t *sigder = auth_data_buf + 32 + 64;

	ret = ctap_parse_make_credential(&MC, encoder, request, length);

	if (ret != 0) {
		printf2(TAG_ERR, "error, parse_make_credential failed\n");
		return ret;
	}
	if (MC.pinAuthEmpty) {
		ret = ctap2_user_presence_test();
		check_retr(ret);
		return ctap_is_pin_set() == 1 ? CTAP2_ERR_PIN_AUTH_INVALID
					      : CTAP2_ERR_PIN_NOT_SET;
	}
	if ((MC.paramsParsed & MC_requiredMask) != MC_requiredMask) {
		printf2(TAG_ERR, "error, required parameter(s) for "
				 "makeCredential are missing\n");
		return CTAP2_ERR_MISSING_PARAMETER;
	}

	if (ctap_is_pin_set() == 1 && MC.pinAuthPresent == 0) {
		printf2(TAG_ERR, "pinAuth is required\n");
		return CTAP2_ERR_PUAT_REQUIRED;
	} else {
		if (ctap_is_pin_set() || (MC.pinAuthPresent)) {
			ret = verify_pin_auth(MC.pinAuth, MC.clientDataHash);
			check_retr(ret);
		}
	}

	if (MC.up == 1 || MC.up == 0) {
		return CTAP2_ERR_INVALID_OPTION;
	}

	uint8_t rp_id_hash[32];
	uint8_t rp_id_lookup[CREDENTIAL_TAG_SIZE];
	derive_rp_id_info(MC.rp.id, MC.rp.size, rp_id_hash, rp_id_lookup);
	printf1(TAG_MC, "rpid:\n");
	dump_hex1(TAG_MC, rp_id_hash, sizeof(rp_id_hash));
	printf1(TAG_MC, "rpid_lookup:\n");
	dump_hex1(TAG_MC, rp_id_lookup, sizeof(rp_id_lookup));

	for (i = 0; i < MC.excludeListSize; i++) {
		ret = parse_credential_descriptor(&MC.excludeList, excl_cred);
		if (ret == CTAP2_ERR_CBOR_UNEXPECTED_TYPE) {
			continue;
		}
		check_retr(ret);

		printf1(TAG_GREEN, "excludeList: checking credId:\n");
		dump_hex1(TAG_GREEN, (uint8_t *)&excl_cred->credential.id,
			  sizeof(CredentialId));

		if (!ctap_authenticate_credential(rp_id_lookup, rp_id_hash,
						  excl_cred)) {
			// Credential does not belong to this token
			continue;
		}

		uint8_t is_rk = 0;
		if (check_credential_metadata(&excl_cred->credential.id,
					      MC.pinAuthPresent, 1,
					      &is_rk) == 0) {

			if (is_rk) {
				if (!verify_rk_exists(
					&excl_cred->credential.id)) {
					// Does not exist, procced with
					// registration
					continue;
				}
			}

			ret = ctap2_user_presence_test();
			check_retr(ret);
			printf1(TAG_MC, "Cred excluded %d\r\n", i);
			return CTAP2_ERR_CREDENTIAL_EXCLUDED;
		}

		ret = cbor_value_advance(&MC.excludeList);
		check_ret(ret);
	}

	CborEncoder map;
	ret = cbor_encoder_create_map(encoder, &map, 3);
	check_ret(ret);

	{
		ret = cbor_encode_int(&map, MC_Resp_fmt);
		check_ret(ret);
		ret = cbor_encode_text_stringz(&map, "packed");
		check_ret(ret);
	}

	uint32_t auth_data_sz = sizeof(auth_data_buf);

	ret = ctap_make_auth_data(&MC.rp, rp_id_hash, rp_id_lookup, &map,
				  auth_data_buf, &auth_data_sz, &MC.credInfo,
				  &MC.extensions);
	check_retr(ret);

	{
		unsigned int ext_encoder_buf_size =
		    sizeof(auth_data_buf) - auth_data_sz;
		uint8_t *ext_encoder_buf = auth_data_buf + auth_data_sz;

		ret = ctap_make_extensions(&MC.extensions, ext_encoder_buf,
					   &ext_encoder_buf_size);
		check_retr(ret);
		if (ext_encoder_buf_size) {
			((CTAP_authData *)auth_data_buf)->head.flags |=
			    (1 << 7);
			auth_data_sz += ext_encoder_buf_size;
		}
	}

	{
		ret = cbor_encode_int(&map, MC_Resp_authData);
		check_ret(ret);
		ret =
		    cbor_encode_byte_string(&map, auth_data_buf, auth_data_sz);
		check_ret(ret);
	}

	crypto_ecc256_load_attestation_key();
	int sigder_sz = ctap_calculate_signature(
	    auth_data_buf, auth_data_sz, MC.clientDataHash, auth_data_buf,
	    sigbuf, sigder, COSE_ALG_ES256);
	printf1(TAG_MC, "der sig [%d]:\n", sigder_sz);
	dump_hex1(TAG_MC, sigder, sigder_sz);

	ret = ctap_add_attest_statement(&map, sigder, sigder_sz);
	check_retr(ret);

	ret = cbor_encoder_close_container(encoder, &map);
	check_ret(ret);
	return CTAP1_ERR_SUCCESS;
}

uint8_t ctap_parse_make_credential(CTAP_makeCredential *MC,
				   CborEncoder *encoder, uint8_t *request,
				   int length)
{
	int ret;
	unsigned int i;
	int key;
	size_t map_length;
	CborParser parser;
	CborValue it, map;

	memset(MC, 0, sizeof(CTAP_makeCredential));
	MC->up = 0xff;
	ret = cbor_parser_init(request, length, CborValidateCanonicalFormat,
			       &parser, &it);
	check_retr(ret);

	CborType type = cbor_value_get_type(&it);
	if (type != CborMapType) {
		printf2(TAG_ERR, "Error, expecting cbor map\n");
		return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
	}

	ret = cbor_value_enter_container(&it, &map);
	check_ret(ret);

	ret = cbor_value_get_map_length(&it, &map_length);
	check_ret(ret);

	printf1(TAG_MC, "map has %d elements\n", map_length);

	for (i = 0; i < map_length; i++) {
		type = cbor_value_get_type(&map);
		if (type != CborIntegerType) {
			printf2(TAG_ERR, "Error, expecting int for map key\n");
			return CTAP2_ERR_CBOR_UNEXPECTED_TYPE;
		}
		ret = cbor_value_get_int_checked(&map, &key);
		check_ret(ret);

		ret = cbor_value_advance(&map);
		check_ret(ret);
		ret = 0;

		switch (key) {

		case MC_Cmd_clientDataHash:
			printf1(TAG_MC, "MC_Cmd_clientDataHash\n");

			ret = parse_fixed_byte_string(&map, MC->clientDataHash,
						      CLIENT_DATA_HASH_SIZE);
			if (ret == 0) {
				MC->paramsParsed |= PARAM_clientDataHash;
			}

			dump_hex1(TAG_MC, MC->clientDataHash, 32);
			break;
		case MC_Cmd_rp:
			printf1(TAG_MC, "MC_Cmd_rp\n");

			ret = parse_rp(&MC->rp, &map);
			if (ret == 0) {
				MC->paramsParsed |= PARAM_rp;
			}

			printf1(TAG_MC, "  ID: %s\n", MC->rp.id);
			printf1(TAG_MC, "  name: %s\n", MC->rp.name);
			break;
		case MC_Cmd_user:
			printf1(TAG_MC, "MC_Cmd_user\n");

			ret = parse_user(MC, &map);

			printf1(TAG_MC, "  ID:\n");
			dump_hex1(TAG_MC, MC->credInfo.user.id,
				  MC->credInfo.user.id_size);
			printf1(TAG_MC, "  name: %s\n", MC->credInfo.user.name);

			break;
		case MC_Cmd_pubKeyCredParams:
			printf1(TAG_MC, "MC_Cmd_pubKeyCredParams\n");

			ret = parse_pub_key_cred_params(MC, &map);

			printf1(TAG_MC, "  cred_type: 0x%02x\n",
				MC->credInfo.publicKeyCredentialType);
			printf1(TAG_MC, "  alg_type: %d\n",
				MC->credInfo.COSEAlgorithmIdentifier);

			break;
		case MC_Cmd_excludeList:
			printf1(TAG_MC, "MC_Cmd_excludeList\n");
			ret = parse_verify_exclude_list(&map);
			check_ret(ret);

			ret =
			    cbor_value_enter_container(&map, &MC->excludeList);
			check_ret(ret);

			ret = cbor_value_get_array_length(&map,
							  &MC->excludeListSize);
			check_ret(ret);

			printf1(TAG_MC, "excludeList done\n");
			break;
		case MC_Cmd_extensions:
			printf1(TAG_MC, "MC_Cmd_extensions\n");
			type = cbor_value_get_type(&map);
			if (type != CborMapType) {
				return CTAP2_ERR_INVALID_CBOR;
			}
			ret = ctap_parse_extensions(&map, &MC->extensions);
			check_retr(ret);
			break;

		case MC_Cmd_options:
			printf1(TAG_MC, "MC_Cmd_options\n");
			ret = parse_options(&map, &MC->credInfo.rk, &MC->uv,
					    &MC->up);
			check_retr(ret);
			break;
		case MC_Cmd_pinUvAuthParam: {
			printf1(TAG_MC, "MC_Cmd_pinUvAuthParam\n");

			size_t pinSize;
			if (cbor_value_get_type(&map) == CborByteStringType &&
			    cbor_value_get_string_length(&map, &pinSize) ==
				CborNoError &&
			    pinSize == 0) {
				MC->pinAuthEmpty = 1;
				break;
			}

			ret = parse_fixed_byte_string(&map, MC->pinAuth, 16);
			if (CTAP1_ERR_INVALID_LENGTH != ret) // damn microsoft
			{
				check_retr(ret);
			} else {
				ret = 0;
			}
			MC->pinAuthPresent = 1;
			break;
		}
		case MC_Cmd_pinUvAuthProtocol:
			printf1(TAG_MC, "MC_Cmd_pinUvAuthProtocol\n");
			if (cbor_value_get_type(&map) == CborIntegerType) {
				ret = cbor_value_get_int_checked(
				    &map, &MC->pinProtocol);
				check_ret(ret);
				printf1(TAG_MC, " == %d\n", MC->pinProtocol);
			} else {
				return CTAP2_ERR_INVALID_CBOR;
			}

			break;

		default:
			printf1(TAG_MC, "invalid key %d\n", key);
		}
		if (ret != 0) {
			return ret;
		}
		ret = cbor_value_advance(&map);
		check_ret(ret);
	}

	return 0;
}

uint8_t parse_pub_key_cred_param(CborValue *val, uint8_t *cred_type,
				 int32_t *alg_type)
{
	CborValue cred;
	CborValue alg;
	int ret;
	uint8_t type_str[16];
	size_t sz = sizeof(type_str);

	if (cbor_value_get_type(val) != CborMapType) {
		printf2(TAG_ERR, "error, expecting map type, got %s\n",
			cbor_value_get_type_string(val));
		return CTAP2_ERR_INVALID_CBOR;
	}

	ret = cbor_value_map_find_value(val, "type", &cred);
	check_ret(ret);
	ret = cbor_value_map_find_value(val, "alg", &alg);
	check_ret(ret);

	if (cbor_value_get_type(&cred) != CborTextStringType) {
		printf2(
		    TAG_ERR,
		    "Error, parse_pub_key could not find credential param\n");
		return CTAP2_ERR_MISSING_PARAMETER;
	}
	if (cbor_value_get_type(&alg) != CborIntegerType) {
		printf2(TAG_ERR,
			"Error, parse_pub_key could not find alg param\n");
		return CTAP2_ERR_MISSING_PARAMETER;
	}

	ret = cbor_value_copy_text_string(&cred, (char *)type_str, &sz, NULL);
	check_ret(ret);

	type_str[sizeof(type_str) - 1] = 0;

	if (strcmp((const char *)type_str, "public-key") == 0) {
		*cred_type = PUB_KEY_CRED_PUB_KEY;
	} else {
		*cred_type = PUB_KEY_CRED_UNKNOWN;
	}

	ret = cbor_value_get_int_checked(&alg, (int *)alg_type);
	check_ret(ret);

	return 0;
}

uint8_t parse_pub_key_cred_params(CTAP_makeCredential *MC, CborValue *val)
{
	size_t arr_length;
	uint8_t cred_type;
	int32_t alg_type;
	int ret;
	unsigned int i;
	CborValue arr;

	if (cbor_value_get_type(val) != CborArrayType) {
		printf2(TAG_ERR, "error, expecting array type\n");
		return CTAP2_ERR_INVALID_CBOR;
	}

	ret = cbor_value_enter_container(val, &arr);
	check_ret(ret);

	ret = cbor_value_get_array_length(val, &arr_length);
	check_ret(ret);

	for (i = 0; i < arr_length; i++) {
		if ((ret = parse_pub_key_cred_param(&arr, &cred_type,
						    &alg_type)) != 0) {
			return ret;
		}
		ret = cbor_value_advance(&arr);
		check_ret(ret);
	}

	ret = cbor_value_enter_container(val, &arr);
	check_ret(ret);

	for (i = 0; i < arr_length; i++) {
		if ((ret = parse_pub_key_cred_param(&arr, &cred_type,
						    &alg_type)) == 0) {
			if (pub_key_cred_param_supported(cred_type, alg_type) ==
			    CREDENTIAL_IS_SUPPORTED) {
				MC->credInfo.publicKeyCredentialType =
				    cred_type;
				MC->credInfo.COSEAlgorithmIdentifier = alg_type;
				MC->paramsParsed |= PARAM_pubKeyCredParams;
				return 0;
			}
		}
		ret = cbor_value_advance(&arr);
		check_ret(ret);
	}

	printf2(TAG_ERR,
		"Error, no public key credential parameters are supported!\n");
	return CTAP2_ERR_UNSUPPORTED_ALGORITHM;
}

uint8_t parse_rp(struct rpId *rp, CborValue *val)
{
	size_t sz, map_length;
	char key[8];
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

	rp->size = 0;

	for (i = 0; i < map_length; i++) {
		if (cbor_value_get_type(&map) != CborTextStringType) {
			printf2(TAG_ERR,
				"Error, expecting text string type for rp map "
				"key, got %s\n",
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

		if (cbor_value_get_type(&map) != CborTextStringType) {
			printf2(TAG_ERR, "Error, expecting text string type "
					 "for rp map value\n");
			return CTAP2_ERR_INVALID_CBOR;
		}

		if (strcmp(key, "id") == 0) {
			ret = parse_rp_id(rp, &map);
			if (ret != 0) {
				return ret;
			}
		} else if (strcmp(key, "name") == 0) {
			sz = RP_NAME_LIMIT;
			ret = cbor_value_copy_text_string(
			    &map, (char *)rp->name, &sz, NULL);
			if (ret != CborErrorOutOfMemory) { // Just truncate the
							   // name it's okay
				check_ret(ret);
			}
			rp->name[RP_NAME_LIMIT - 1] = 0;
		} else {
			printf1(TAG_PARSE, "ignoring key %s for RP map\n", key);
		}

		ret = cbor_value_advance(&map);
		check_ret(ret);
	}
	if (rp->size == 0) {
		printf2(TAG_ERR, "Error, no RPID provided\n");
		return CTAP2_ERR_MISSING_PARAMETER;
	}

	return 0;
}

uint8_t parse_user(CTAP_makeCredential *MC, CborValue *val)
{
	size_t sz, map_length;
	uint8_t key[24];
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
		if (cbor_value_get_type(&map) != CborTextStringType) {
			printf2(TAG_ERR,
				"Error, expecting text string type for user "
				"map key, got %s\n",
				cbor_value_get_type_string(&map));
			return CTAP2_ERR_INVALID_CBOR;
		}

		sz = sizeof(key);
		ret = cbor_value_copy_text_string(&map, (char *)key, &sz, NULL);

		if (ret == CborErrorOutOfMemory) {
			printf2(TAG_ERR, "Error, rp map key is too large\n");
			return CTAP2_ERR_LIMIT_EXCEEDED;
		}

		check_ret(ret);
		key[sizeof(key) - 1] = 0;

		ret = cbor_value_advance(&map);
		check_ret(ret);

		if (strcmp((const char *)key, "id") == 0) {

			if (cbor_value_get_type(&map) != CborByteStringType) {
				printf2(TAG_ERR, "Error, expecting byte string "
						 "type for rp map value\n");
				return CTAP2_ERR_INVALID_CBOR;
			}

			sz = USER_ID_MAX_SIZE;
			ret = cbor_value_copy_byte_string(
			    &map, MC->credInfo.user.id, &sz, NULL);
			if (ret == CborErrorOutOfMemory) {
				printf2(TAG_ERR,
					"Error, USER_ID is too large\n");
				return CTAP2_ERR_LIMIT_EXCEEDED;
			}
			MC->credInfo.user.id_size = sz;
			check_ret(ret);
		} else if (strcmp((const char *)key, "name") == 0) {
			if (cbor_value_get_type(&map) != CborTextStringType) {
				printf2(TAG_ERR, "Error, expecting text string "
						 "type for user.name value\n");
				return CTAP2_ERR_INVALID_CBOR;
			}
			sz = USER_NAME_LIMIT;
			ret = cbor_value_copy_text_string(
			    &map, (char *)MC->credInfo.user.name, &sz, NULL);
			if (ret != CborErrorOutOfMemory) { // Just truncate the
							   // name it's okay
				check_ret(ret);
			}
			MC->credInfo.user.name[USER_NAME_LIMIT - 1] = 0;
		} else if (strcmp((const char *)key, "displayName") == 0) {
			if (cbor_value_get_type(&map) != CborTextStringType) {
				printf2(TAG_ERR,
					"Error, expecting text string type for "
					"user.displayName value\n");
				return CTAP2_ERR_INVALID_CBOR;
			}
			sz = DISPLAY_NAME_LIMIT;
			ret = cbor_value_copy_text_string(
			    &map, (char *)MC->credInfo.user.displayName, &sz,
			    NULL);
			if (ret != CborErrorOutOfMemory) { // Just truncate the
							   // name it's okay
				check_ret(ret);
			}
			MC->credInfo.user.displayName[DISPLAY_NAME_LIMIT - 1] =
			    0;
		} else if (strcmp((const char *)key, "icon") == 0) {
			// Icon is deprecated, don't store it.
			// Still need to parse it and return error if it is
			// malformed.

			if (cbor_value_get_type(&map) != CborTextStringType) {
				printf2(TAG_ERR, "Error, expecting text string "
						 "type for user.icon value\n");
				return CTAP2_ERR_INVALID_CBOR;
			}

		} else {
			printf1(TAG_PARSE, "ignoring key %s for user map\n",
				key);
		}

		ret = cbor_value_advance(&map);
		check_ret(ret);
	}

	MC->paramsParsed |= PARAM_user;

	return 0;
}

uint8_t parse_verify_exclude_list(CborValue *val)
{
	unsigned int i;
	int ret;
	CborValue arr;
	size_t size;
	CTAP_credentialDescriptor cred;
	if (cbor_value_get_type(val) != CborArrayType) {
		printf2(TAG_ERR, "error, exclude list is not a map\n");
		return CTAP2_ERR_INVALID_CBOR;
	}
	ret = cbor_value_get_array_length(val, &size);
	check_ret(ret);
	ret = cbor_value_enter_container(val, &arr);
	check_ret(ret);
	for (i = 0; i < size; i++) {
		ret = parse_credential_descriptor(&arr, &cred);
		check_ret(ret);
		ret = cbor_value_advance(&arr);
		check_ret(ret);
	}
	return 0;
}

// Check if public key credential+algorithm type is supported
int pub_key_cred_param_supported(uint8_t cred, int32_t alg)
{
	if (cred == PUB_KEY_CRED_PUB_KEY) {
		if (alg == COSE_ALG_ES256 || alg == COSE_ALG_EDDSA) {
			return CREDENTIAL_IS_SUPPORTED;
		}
	}

	return CREDENTIAL_NOT_SUPPORTED;
}
