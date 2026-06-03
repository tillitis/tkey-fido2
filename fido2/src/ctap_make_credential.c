// SPDX-FileCopyrightText: 2019 SoloKeys Developers
// SPDX-FileCopyrightText: 2026 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: Apache-2.0 OR MIT

#include <stdint.h>

#include "attestation.h"
#include "crypto.h"
#include "ctap.h"
#include "ctap_client_pin.h"
#include "ctap_errors.h"
#include "ctap_make_credential.h"
#include "ctap_parse.h"
#include "log.h"

static CtapStatus cbor_encode_attestation_statement(CborEncoder *map,
						    uint8_t *sigder,
						    size_t len);
static CtapStatus
find_supported_pubkey_credential_param(CTAP_makeCredential *MC, CborValue *val);
static int
is_pubkey_credential_param_supported(PublicKeyCredentialType credtype,
				     COSEAlgorithmIdentifier algtype);
static CtapStatus parse_exclude_list(CborValue *val);
static CtapStatus parse_make_credential(CTAP_makeCredential *MC,
					uint8_t *request, size_t length);
static CtapStatus
parse_pubkey_credential_params(CborValue *val,
			       PublicKeyCredentialType *credtype,
			       COSEAlgorithmIdentifier *algtype);
static CtapStatus parse_relying_party_entity(struct rpId *rp, CborValue *val);

CtapStatus ctap_make_credential(CborEncoder *encoder, uint8_t *request,
				size_t length)
{
	CTAP_makeCredential MC;
	CborError cbor_ret;
	CtapStatus ctap_ret;
	unsigned int i;
	uint8_t auth_data_buf[310];
	CTAP_credentialDescriptor *excl_cred =
	    (CTAP_credentialDescriptor *)auth_data_buf;
	uint8_t *sigbuf = auth_data_buf + 32;
	uint8_t *sigder = auth_data_buf + 32 + 64;

	ctap_ret = parse_make_credential(&MC, request, length);
	if (ctap_ret.value != CTAP2_OK) {
		printf2(TAG_ERR, "Error, parse_make_credential() failed\n");
		return ctap_ret;
	}
	if (MC.pinUvAuthParam_empty) {
		ctap_ret = ctap2_user_presence_test();
		ctap_check_retr(ctap_ret);
		return ctap_client_pin_is_set() == 1
			   ? (CtapStatus){CTAP2_ERR_PIN_AUTH_INVALID}
			   : (CtapStatus){CTAP2_ERR_PIN_NOT_SET};
	}
	if ((MC.paramsParsed & MC_requiredMask) != MC_requiredMask) {
		printf2(TAG_ERR, "Error, required parameter(s) for "
				 "makeCredential are missing\n");
		return (CtapStatus){CTAP2_ERR_MISSING_PARAMETER};
	}

	// TODO:: This needs to be verified against spec
	if (ctap_client_pin_is_set()) {
		if (MC.pinUvAuthParam_present == 0) {
			printf2(TAG_ERR, "Error, pinUvAuthParam is required\n");
			return (CtapStatus){CTAP2_ERR_PUAT_REQUIRED};
		}

		if (ctap_client_pin_is_set() || (MC.pinUvAuthParam_present)) {
			ctap_ret = ctap_client_pin_verify_auth(
			    MC.pinUvAuthParam, MC.clientDataHash,
			    MC.pinProtocol);
			ctap_check_retr(ctap_ret);
		}

		if (!ctap_client_pin_get_user_verified(MC.pinProtocol)) {
			printf2(TAG_ERR, "User not verified\n");
			return (CtapStatus){CTAP2_ERR_PIN_AUTH_INVALID};
		}

		if (!ctap_client_pin_verify_permissions(
			MC.pinProtocol, CP_pinUvAuthToken_permissions_mc)) {
			printf2(TAG_ERR, "Permissions not verified\n");
			return (CtapStatus){CTAP2_ERR_PIN_AUTH_INVALID};
		}
	}

	// Not allowed to to request with up set to false.
	if (MC.up == 0) {
		return (CtapStatus){CTAP2_ERR_INVALID_OPTION};
	}

	uint8_t rp_id_hash[32];
	uint8_t rp_id_lookup[CREDENTIAL_TAG_SIZE];
	ctap_derive_rp_id_info(MC.rp.id, MC.rp.size, rp_id_hash, rp_id_lookup);
	printf1(TAG_MC, "rpid:\n");
	dump_hex1(TAG_MC, rp_id_hash, sizeof(rp_id_hash));
	printf1(TAG_MC, "rpid_lookup:\n");
	dump_hex1(TAG_MC, rp_id_lookup, sizeof(rp_id_lookup));

	if (ctap_client_pin_is_set()) {
		// We need to calculate rp id hash first.
		if (false == ctap_client_pin_verify_permissions_rp_id(
				 MC.pinProtocol, rp_id_hash)) {
			return (CtapStatus){CTAP2_ERR_PIN_AUTH_INVALID};
		}
	}

	for (i = 0; i < MC.excludeListSize; i++) {
		ctap_ret = ctap_parse_pubkey_credential_descriptor(
		    &MC.excludeList, excl_cred);
		if (ctap_ret.value == CTAP2_ERR_CBOR_UNEXPECTED_TYPE) {
			continue;
		}
		ctap_check_retr(ctap_ret);

		printf1(TAG_GREEN, "excludeList: checking credId:\n");
		dump_hex1(TAG_GREEN, (uint8_t *)&excl_cred->credential.id,
			  sizeof(CredentialId));

		if (!ctap_credential_belongs_to_rp(rp_id_lookup, rp_id_hash,
						   excl_cred)) {
			// Credential does not belong to this token
			continue;
		}

		uint8_t is_rk = 0;
		if (ctap_check_credential_metadata(&excl_cred->credential.id,
						   MC.pinUvAuthParam_present, 1,
						   &is_rk) == 0) {

			if (is_rk) {
				if (!ctap_verify_rk_exists(
					&excl_cred->credential.id)) {
					// Does not exist, proceed with
					// registration
					continue;
				}
			}

			ctap_ret = ctap2_user_presence_test();
			ctap_check_retr(ctap_ret);
			printf1(TAG_MC, "Cred excluded %d\n", i);
			return (CtapStatus){CTAP2_ERR_CREDENTIAL_EXCLUDED};
		}

		cbor_ret = cbor_value_advance(&MC.excludeList);
		cbor_check_ret(cbor_ret);
	}

	CborEncoder map;
	// Encode in Canonical CBOR order: "fmt", "authdata", "attstmt"
	cbor_ret = cbor_encoder_create_map(encoder, &map, 3);
	cbor_check_ret(cbor_ret);

	cbor_ret = cbor_encode_int(&map, MC_Resp_fmt);
	cbor_check_ret(cbor_ret);

	// Check if attestation is available
	if (crypto_attestation_available()) {
		cbor_ret = cbor_encode_text_stringz(&map, "packed");
	} else {
		cbor_ret = cbor_encode_text_stringz(&map, "none");
	}

	cbor_check_ret(cbor_ret);

	size_t auth_data_sz = sizeof(auth_data_buf);

	ctap_ret =
	    ctap_make_auth_data(&MC.rp, rp_id_hash, rp_id_lookup, auth_data_buf,
				&auth_data_sz, &MC.credInfo, &MC.extensions);
	ctap_check_retr(ctap_ret);

	// TODO: Should be done in collaboration with the user presence. Should
	// probably be refactored The UP option should always be true here. 0xff
	// indicates that it is true by default

	ctap_client_pin_clear_user_present(MC.pinProtocol);
	ctap_client_pin_clear_user_verified(MC.pinProtocol);
	ctap_client_pin_clear_PinUvAuthToken_permissions_except_Lbw(
	    MC.pinProtocol);

	{
		unsigned int ext_encoder_buf_size =
		    sizeof(auth_data_buf) - auth_data_sz;
		uint8_t *ext_encoder_buf = auth_data_buf + auth_data_sz;

		ctap_ret = ctap_extensions_encode_output(
		    &MC.extensions, ext_encoder_buf, &ext_encoder_buf_size);
		ctap_check_retr(ctap_ret);
		if (ext_encoder_buf_size) {
			((CTAP_authData *)auth_data_buf)->head.flags |=
			    (1 << 7);
			auth_data_sz += ext_encoder_buf_size;
		}
	}

	{
		cbor_ret = cbor_encode_int(&map, MC_Resp_authData);
		cbor_check_ret(cbor_ret);
		cbor_ret =
		    cbor_encode_byte_string(&map, auth_data_buf, auth_data_sz);
		cbor_check_ret(cbor_ret);
	}

	size_t sigder_sz = 0;

	if (crypto_attestation_available()) {
		crypto_ecc256_load_attestation_key();
		sigder_sz = ctap_sign_data(auth_data_buf, auth_data_sz,
					   MC.clientDataHash, sigbuf, sigder,
					   COSE_ALG_ES256);
		printf1(TAG_MC, "der sig [%d]:\n", sigder_sz);
		dump_hex1(TAG_MC, sigder, sigder_sz);
	} else {
		printf1(TAG_MC, "Skipping attest signature\n");
	}

	ctap_ret = cbor_encode_attestation_statement(&map, sigder, sigder_sz);
	ctap_check_retr(ctap_ret);

	cbor_ret = cbor_encoder_close_container(encoder, &map);
	cbor_check_ret(cbor_ret);

	return (CtapStatus){CTAP2_OK};
}

static CtapStatus cbor_encode_attestation_statement(CborEncoder *map,
						    uint8_t *sigder, size_t len)
{
	int ret;
	CborError cbor_ret;
	CborEncoder stmtmap;

	cbor_ret = cbor_encode_int(map, MC_Resp_attStmt);
	cbor_check_ret(cbor_ret);

	if (crypto_attestation_available()) {
		uint8_t cert[ATTESTATION_MAX_CERT_SIZE];
		size_t cert_size;

		ret = attestation_read_cert(cert, ATTESTATION_MAX_CERT_SIZE,
					    &cert_size);
		if (ret < 0) {
			printf2(TAG_GREEN,
				"Certificate read failed %d (size: %d)\n", ret,
				cert_size);
			return (CtapStatus){CTAP1_ERR_OTHER};
		}

		CborEncoder x5carr;

		cbor_ret = cbor_encoder_create_map(map, &stmtmap, 3);
		cbor_check_ret(cbor_ret);
		{
			cbor_ret = cbor_encode_text_stringz(&stmtmap, "alg");
			cbor_check_ret(cbor_ret);
			cbor_ret = cbor_encode_int(&stmtmap, COSE_ALG_ES256);
			cbor_check_ret(cbor_ret);
		}
		{
			cbor_ret = cbor_encode_text_stringz(&stmtmap, "sig");
			cbor_check_ret(cbor_ret);
			cbor_ret =
			    cbor_encode_byte_string(&stmtmap, sigder, len);
			cbor_check_ret(cbor_ret);
		}
		{
			cbor_ret = cbor_encode_text_stringz(&stmtmap, "x5c");
			cbor_check_ret(cbor_ret);
			cbor_ret =
			    cbor_encoder_create_array(&stmtmap, &x5carr, 1);
			cbor_check_ret(cbor_ret);
			{
				cbor_ret = cbor_encode_byte_string(
				    &x5carr, cert, cert_size);
				cbor_check_ret(cbor_ret);
				cbor_ret = cbor_encoder_close_container(
				    &stmtmap, &x5carr);
				cbor_check_ret(cbor_ret);
			}
		}
	} else {

		cbor_ret = cbor_encoder_create_map(map, &stmtmap, 0);
		cbor_check_ret(cbor_ret);
	}

	cbor_ret = cbor_encoder_close_container(map, &stmtmap);
	cbor_check_ret(cbor_ret);
	return (CtapStatus){CTAP2_OK};
}

static CtapStatus
find_supported_pubkey_credential_param(CTAP_makeCredential *MC, CborValue *val)
{
	size_t arr_length;
	PublicKeyCredentialType credtype;
	COSEAlgorithmIdentifier algtype;
	CborError cbor_ret;
	CtapStatus ctap_ret;
	unsigned int i;
	CborValue arr;

	if (cbor_value_get_type(val) != CborArrayType) {
		printf2(TAG_ERR, "Error, expecting cbor array\n");
		return (CtapStatus){CTAP2_ERR_INVALID_CBOR};
	}

	cbor_ret = cbor_value_enter_container(val, &arr);
	cbor_check_ret(cbor_ret);

	cbor_ret = cbor_value_get_array_length(val, &arr_length);
	cbor_check_ret(cbor_ret);

	for (i = 0; i < arr_length; i++) {
		ctap_ret =
		    parse_pubkey_credential_params(&arr, &credtype, &algtype);
		if (ctap_ret.value != CTAP2_OK) {
			return ctap_ret;
		}
		cbor_ret = cbor_value_advance(&arr);
		cbor_check_ret(cbor_ret);
	}

	cbor_ret = cbor_value_enter_container(val, &arr);
	cbor_check_ret(cbor_ret);

	for (i = 0; i < arr_length; i++) {
		ctap_ret =
		    parse_pubkey_credential_params(&arr, &credtype, &algtype);
		if (ctap_ret.value == CTAP2_OK) {
			if (is_pubkey_credential_param_supported(
				credtype, algtype) == CREDENTIAL_IS_SUPPORTED) {
				MC->credInfo.publicKeyCredentialType = credtype;
				MC->credInfo.coseAlgorithmIdentifier = algtype;
				MC->paramsParsed |= PARAM_pubKeyCredParams;
				return (CtapStatus){CTAP2_OK};
			}
		}
		cbor_ret = cbor_value_advance(&arr);
		cbor_check_ret(cbor_ret);
	}

	printf2(TAG_ERR,
		"Error, no public key credential parameters are supported!\n");
	return (CtapStatus){CTAP2_ERR_UNSUPPORTED_ALGORITHM};
}

// Check if public key credential+algorithm type is supported
static int
is_pubkey_credential_param_supported(PublicKeyCredentialType credtype,
				     COSEAlgorithmIdentifier algtype)
{
	if (credtype == PUB_KEY_CRED_PUB_KEY) {
		if (algtype == COSE_ALG_ES256 || algtype == COSE_ALG_EDDSA) {
			return CREDENTIAL_IS_SUPPORTED;
		}
	}

	return CREDENTIAL_NOT_SUPPORTED;
}

static CtapStatus parse_exclude_list(CborValue *val)
{
	unsigned int i;
	CborError cbor_ret;
	CtapStatus ctap_ret;
	CborValue arr;
	size_t size;
	CTAP_credentialDescriptor cred;
	if (cbor_value_get_type(val) != CborArrayType) {
		printf2(TAG_ERR, "Error, exclude list is not a map\n");
		return (CtapStatus){CTAP2_ERR_INVALID_CBOR};
	}
	cbor_ret = cbor_value_get_array_length(val, &size);
	cbor_check_ret(cbor_ret);
	cbor_ret = cbor_value_enter_container(val, &arr);
	cbor_check_ret(cbor_ret);
	for (i = 0; i < size; i++) {
		ctap_ret = ctap_parse_pubkey_credential_descriptor(&arr, &cred);
		ctap_check_retr(ctap_ret);

		cbor_ret = cbor_value_advance(&arr);
		cbor_check_ret(cbor_ret);
	}
	return (CtapStatus){CTAP2_OK};
}

static CtapStatus parse_make_credential(CTAP_makeCredential *MC,
					uint8_t *request, size_t length)
{
	CborError cbor_ret;
	CtapStatus ctap_ret = (CtapStatus){CTAP2_OK};
	unsigned int i;
	int key;
	size_t map_length;
	CborParser parser;
	CborValue it, map;

	memset(MC, 0, sizeof(CTAP_makeCredential));
	MC->up = 1; // Default is true, register if platform sends 0
	cbor_ret = cbor_parser_init(request, length,
				    CborValidateCanonicalFormat, &parser, &it);
	cbor_check_ret(cbor_ret);

	if (cbor_value_get_type(&it) != CborMapType) {
		printf2(TAG_ERR, "Error, expecting cbor map\n");
		return (CtapStatus){CTAP2_ERR_CBOR_UNEXPECTED_TYPE};
	}

	cbor_ret = cbor_value_enter_container(&it, &map);
	cbor_check_ret(cbor_ret);

	cbor_ret = cbor_value_get_map_length(&it, &map_length);
	cbor_check_ret(cbor_ret);

	printf1(TAG_MC, "map has %d elements\n", map_length);

	for (i = 0; i < map_length; i++) {
		if (cbor_value_get_type(&map) != CborIntegerType) {
			printf2(TAG_ERR, "Error, expecting int for map key\n");
			return (CtapStatus){CTAP2_ERR_CBOR_UNEXPECTED_TYPE};
		}
		cbor_ret = cbor_value_get_int_checked(&map, &key);
		cbor_check_ret(cbor_ret);

		cbor_ret = cbor_value_advance(&map);
		cbor_check_ret(cbor_ret);
		cbor_ret = CborNoError;

		switch (key) {

		case MC_Cmd_clientDataHash:
			printf1(TAG_MC, "MC_Cmd_clientDataHash\n");

			ctap_ret = ctap_parse_fixed_length_byte_string(
			    &map, MC->clientDataHash, CLIENT_DATA_HASH_SIZE);
			if (ctap_ret.value == CTAP2_OK) {
				MC->paramsParsed |= PARAM_clientDataHash;
			}

			dump_hex1(TAG_MC, MC->clientDataHash, 32);
			break;

		case MC_Cmd_rp:
			printf1(TAG_MC, "MC_Cmd_rp\n");

			ctap_ret = parse_relying_party_entity(&MC->rp, &map);
			if (ctap_ret.value == CTAP2_OK) {
				MC->paramsParsed |= PARAM_rp;
			}

			printf1(TAG_MC, "  ID: %s\n", MC->rp.id);
			printf1(TAG_MC, "  name: %s\n", MC->rp.name);
			break;

		case MC_Cmd_user:
			printf1(TAG_MC, "MC_Cmd_user\n");

			ctap_ret =
			    ctap_parse_user_entity(&MC->credInfo.user, &map);
			if (ctap_ret.value == CTAP2_OK) {
				MC->paramsParsed |= PARAM_user;
			}

			printf1(TAG_MC, "  ID:\n");
			dump_hex1(TAG_MC, MC->credInfo.user.id,
				  MC->credInfo.user.id_size);
			printf1(TAG_MC, "  name: %s\n", MC->credInfo.user.name);
			break;

		case MC_Cmd_pubKeyCredParams:
			printf1(TAG_MC, "MC_Cmd_pubKeyCredParams\n");

			ctap_ret =
			    find_supported_pubkey_credential_param(MC, &map);

			printf1(TAG_MC, "  cred_type: 0x%02x\n",
				MC->credInfo.publicKeyCredentialType);
			printf1(TAG_MC, "  alg_type: %d\n",
				MC->credInfo.coseAlgorithmIdentifier);
			break;

		case MC_Cmd_excludeList:
			printf1(TAG_MC, "MC_Cmd_excludeList\n");
			ctap_ret = parse_exclude_list(&map);
			ctap_check_retr(ctap_ret);

			cbor_ret =
			    cbor_value_enter_container(&map, &MC->excludeList);
			cbor_check_ret(cbor_ret);

			cbor_ret = cbor_value_get_array_length(
			    &map, &MC->excludeListSize);
			cbor_check_ret(cbor_ret);

			printf1(TAG_MC, "excludeList done\n");
			break;

		case MC_Cmd_extensions:
			printf1(TAG_MC, "MC_Cmd_extensions\n");
			if (cbor_value_get_type(&map) != CborMapType) {
				printf2(TAG_ERR, "Error, expecting cbor map\n");
				return (CtapStatus){CTAP2_ERR_INVALID_CBOR};
			}
			ctap_ret =
			    ctap_extensions_parse_input(&map, &MC->extensions);
			ctap_check_retr(ctap_ret);
			break;

		case MC_Cmd_options:
			printf1(TAG_MC, "MC_Cmd_options\n");
			ctap_ret = ctap_parse_options(&map, &MC->credInfo.rk,
						      &MC->uv, &MC->up);
			ctap_check_retr(ctap_ret);
			break;

		case MC_Cmd_pinUvAuthParam:
			printf1(TAG_MC, "MC_Cmd_pinUvAuthParam\n");

			size_t pinSize;
			if (cbor_value_get_type(&map) == CborByteStringType &&
			    cbor_value_get_string_length(&map, &pinSize) ==
				CborNoError &&
			    pinSize == 0) {
				MC->pinUvAuthParam_empty = 1;
				break;
			}

			ctap_ret = ctap_parse_fixed_length_byte_string(
			    &map, MC->pinUvAuthParam,
			    PIN_UV_AUTH_PARAM_MAX_SIZE);
			if (CTAP1_ERR_INVALID_LENGTH !=
			    ctap_ret.value) // damn microsoft
			{
				ctap_check_retr(ctap_ret);
			} else {
				ctap_ret.value = CTAP2_OK;
			}
			MC->pinUvAuthParam_present = 1;
			break;

		case MC_Cmd_pinUvAuthProtocol:
			printf1(TAG_MC, "MC_Cmd_pinUvAuthProtocol\n");
			if (cbor_value_get_type(&map) != CborIntegerType) {
				return (CtapStatus){CTAP2_ERR_INVALID_CBOR};
			}
			int tmp;
			cbor_ret = cbor_value_get_int_checked(&map, &tmp);
			cbor_check_ret(cbor_ret);
			if (tmp < 0 || tmp > (int)UINT8_MAX) {
				return (CtapStatus){CTAP2_ERR_INVALID_CBOR};
			}
			MC->pinProtocol = (uint8_t)tmp;

			printf1(TAG_MC, " == %d\n", MC->pinProtocol);
			break;

		default:
			printf1(TAG_MC, "invalid key %d\n", key);
		}

		ctap_check_retr(ctap_ret);

		cbor_ret = cbor_value_advance(&map);
		cbor_check_ret(cbor_ret);
	}

	return (CtapStatus){CTAP2_OK};
}

static CtapStatus
parse_pubkey_credential_params(CborValue *val,
			       PublicKeyCredentialType *credtype,
			       COSEAlgorithmIdentifier *algtype)
{
	CborValue cred;
	CborValue alg;
	CborError cbor_ret;
	uint8_t type_str[16];
	size_t sz = sizeof(type_str);

	if (cbor_value_get_type(val) != CborMapType) {
		printf2(TAG_ERR, "Error, expecting cbor map, got %s\n",
			cbor_value_get_type_string(val));
		return (CtapStatus){CTAP2_ERR_INVALID_CBOR};
	}

	cbor_ret = cbor_value_map_find_value(val, "type", &cred);
	cbor_check_ret(cbor_ret);
	cbor_ret = cbor_value_map_find_value(val, "alg", &alg);
	cbor_check_ret(cbor_ret);

	if (cbor_value_get_type(&cred) != CborTextStringType) {
		printf2(TAG_ERR, "Error, could not find credential param\n");
		return (CtapStatus){CTAP2_ERR_MISSING_PARAMETER};
	}

	if (cbor_value_get_type(&alg) != CborIntegerType) {
		printf2(TAG_ERR, "Error, could not find alg param\n");
		return (CtapStatus){CTAP2_ERR_MISSING_PARAMETER};
	}

	cbor_ret =
	    cbor_value_copy_text_string(&cred, (char *)type_str, &sz, NULL);
	cbor_check_ret(cbor_ret);

	type_str[sizeof(type_str) - 1] = 0;

	if (strcmp((const char *)type_str, "public-key") == 0) {
		*credtype = PUB_KEY_CRED_PUB_KEY;
	} else {
		*credtype = PUB_KEY_CRED_UNKNOWN;
	}

	cbor_ret = cbor_value_get_int_checked(&alg, (int *)algtype);
	cbor_check_ret(cbor_ret);

	return (CtapStatus){CTAP2_OK};
}

static CtapStatus parse_relying_party_entity(struct rpId *rp, CborValue *val)
{
	size_t sz, map_length;
	char key[8];
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

	rp->size = 0;

	for (i = 0; i < map_length; i++) {
		if (cbor_value_get_type(&map) != CborTextStringType) {
			printf2(TAG_ERR,
				"Error, expecting text string type for rp map "
				"key, got %s\n",
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

		if (cbor_value_get_type(&map) != CborTextStringType) {
			printf2(TAG_ERR, "Error, expecting text string type "
					 "for rp map value\n");
			return (CtapStatus){CTAP2_ERR_INVALID_CBOR};
		}

		if (strcmp(key, "id") == 0) {
			ctap_ret = ctap_parse_rp_id(rp, &map);
			if (ctap_ret.value != CTAP2_OK) {
				return ctap_ret;
			}
		} else if (strcmp(key, "name") == 0) {
			sz = RP_NAME_LIMIT;
			cbor_ret = cbor_value_copy_text_string(
			    &map, (char *)rp->name, &sz, NULL);
			if (cbor_ret !=
			    CborErrorOutOfMemory) { // Just truncate the
						    // name it's okay
				cbor_check_ret(cbor_ret);
			}
			rp->name[RP_NAME_LIMIT - 1] = 0;
		} else {
			printf1(TAG_PARSE, "ignoring key %s for RP map\n", key);
		}

		cbor_ret = cbor_value_advance(&map);
		cbor_check_ret(cbor_ret);
	}
	if (rp->size == 0) {
		printf2(TAG_ERR, "Error, no RPID provided\n");
		return (CtapStatus){CTAP2_ERR_MISSING_PARAMETER};
	}

	return (CtapStatus){CTAP2_OK};
}
