// SPDX-FileCopyrightText: 2019 SoloKeys Developers
// SPDX-FileCopyrightText: 2026 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: Apache-2.0 OR MIT

#include <stdint.h>
#include <stdlib.h>

#include "crypto.h"
#include "ctap_client_pin.h"
#include "ctap_errors.h"
#include "ctap_get_assertion.h"
#include "ctap_make_credential.h"
#include "ctap_parse.h"
#include "device.h"
#include "log.h"

extern struct _getAssertionState getAssertionState;

static size_t build_filtered_credential_list(CTAP_getAssertion *GA,
					     uint8_t *rp_id_hash,
					     uint8_t *rp_id_lookup);
static int cred_cmp_func(const void *_a, const void *_b);
static CtapStatus parse_allow_list_credentials(CTAP_getAssertion *GA,
					       CborValue *it);
static CtapStatus parse_get_assertion_request(CTAP_getAssertion *GA,
					      uint8_t *request, size_t length);
static CtapStatus save_credential_list(uint8_t *clientDataHash,
				       CTAP_credentialDescriptor *creds,
				       uint32_t count,
				       CTAP_extensions *extensions);

CtapStatus ctap_get_assertion(CborEncoder *encoder, uint8_t *request,
			      size_t length)
{
	CborError cbor_ret;
	CtapStatus ctap_ret;
	CTAP_getAssertion GA;

	ctap_ret = parse_get_assertion_request(&GA, request, length);

	if (ctap_ret.value != CTAP2_OK) {
		printf2(TAG_ERR,
			"Error, parse_get_assertion_request() failed\n");
		return ctap_ret;
	}

	if (GA.pinUvAuthParam_empty) {
		ctap_ret = ctap2_user_presence_test();
		// TODO: should return CTAP2_ERR_OPERATION_DENIED if declined or
		// timeout. see 6.2.2.2
		ctap_check_retr(ctap_ret);

		return ctap_client_pin_is_set() == 1
			   ? (CtapStatus){CTAP2_ERR_PIN_AUTH_INVALID}
			   : (CtapStatus){CTAP2_ERR_PIN_NOT_SET};
	}

	// RPID and clientDataHash are always mandatory
	if (!GA.rp.size || !GA.clientDataHashPresent) {
		return (CtapStatus){CTAP2_ERR_MISSING_PARAMETER};
	}

	uint8_t rp_id_hash[32];
	uint8_t rp_id_lookup[CREDENTIAL_TAG_SIZE];
	ctap_derive_rp_id_info(GA.rp.id, GA.rp.size, rp_id_hash, rp_id_lookup);

	// If pinUvAuthParam is present and the authenticator is protected, do
	// verification. If not, continue but set user_verifier = 0.
	if (GA.pinUvAuthParam_len > 0) {
		if (GA.pinProtocol == 0) {
			return (CtapStatus){CTAP2_ERR_MISSING_PARAMETER};
		}
		ctap_ret = ctap_client_pin_verify_auth(
		    GA.pinUvAuthParam, GA.clientDataHash, GA.pinProtocol);
		ctap_check_retr(ctap_ret);

		if (!ctap_client_pin_get_user_verified(GA.pinProtocol)) {
			return (CtapStatus){CTAP2_ERR_PIN_AUTH_INVALID};
		}

		if (!ctap_client_pin_verify_permissions(
			GA.pinProtocol, CP_pinUvAuthToken_permissions_ga)) {
			return (CtapStatus){CTAP2_ERR_PIN_AUTH_INVALID};
		}

		if (false == ctap_client_pin_verify_permissions_rp_id(
				 GA.pinProtocol, rp_id_hash)) {
			return (CtapStatus){CTAP2_ERR_PIN_AUTH_INVALID};
		}

		getAssertionState.user_verified = 1;
	} else {
		getAssertionState.user_verified = 0;
	}

	CborEncoder map;

	size_t map_size = 3;

	printf1(TAG_GA, "rpid:\n");
	dump_hex1(TAG_GA, rp_id_hash, sizeof(rp_id_hash));
	printf1(TAG_GA, "rpid_lookup:\n");
	dump_hex1(TAG_GA, rp_id_lookup, sizeof(rp_id_lookup));

	printf1(TAG_GA, "ALLOW_LIST has %d creds\n", GA.credLen);
	size_t validCredCount =
	    build_filtered_credential_list(&GA, rp_id_hash, rp_id_lookup);

	if (validCredCount == 0) {
		printf2(TAG_ERR, "Error, no authentic credential\n");
		return (CtapStatus){CTAP2_ERR_NO_CREDENTIALS};
	} else if (validCredCount > 1) {
		map_size += 1;
	}

	printf1(TAG_GREEN, "2 USER ID SIZE: %d\n",
		GA.creds[0].credential.user.id_size);

	if (GA.creds[validCredCount - 1].credential.user.id_size) {
		map_size += 1;
	}
	if (GA.extensions.hmac_secret_present == EXT_HMAC_SECRET_PARSED) {
		printf1(TAG_GA, "hmac-secret is present\n");
	}

	cbor_ret = cbor_encoder_create_map(encoder, &map, map_size);
	cbor_check_ret(cbor_ret);

	// if only one account for this RP, null out the user details
	if (validCredCount < 2 || !getAssertionState.user_verified) {
		printf1(TAG_GREEN, "Only one account, nulling out user details "
				   "on response\n");
		memset(&GA.creds[0].credential.user.name, 0, USER_NAME_LIMIT);
	}

	printf1(TAG_GA, "resulting order of creds:\n");
	size_t j;
	for (j = 0; j < GA.credLen; j++) {
		printf1(TAG_GA, "CRED ID (# %d)\n",
			GA.creds[j].credential.id.count);
	}

	CTAP_credentialDescriptor *cred = &GA.creds[0];

	GA.extensions.hmac_secret.credential = &cred->credential;

	size_t auth_data_buf_sz = sizeof(CTAP_authDataHeader);

	{
		device_disable_up(GA.up == 0);
		ctap_ret = ctap_make_auth_data(
		    &GA.rp, rp_id_hash, rp_id_lookup,
		    (uint8_t *)&getAssertionState.buf.authData,
		    &auth_data_buf_sz, NULL, &GA.extensions);
		device_disable_up(false);
		ctap_check_retr(ctap_ret);

		// If the "up" option is set to true or not present - clear the
		// pin flags
		if (GA.up == 1 || GA.up == 0xff) {
			ctap_client_pin_clear_user_present(GA.pinProtocol);
			ctap_client_pin_clear_user_verified(GA.pinProtocol);
			ctap_client_pin_clear_PinUvAuthToken_permissions_except_Lbw(
			    GA.pinProtocol);
		}

		// Update UV-bit
		getAssertionState.buf.authData.flags &= ~(1 << 2);
		getAssertionState.buf.authData.flags |=
		    (getAssertionState.user_verified << 2);

		{
			unsigned int ext_encoder_buf_size =
			    sizeof(getAssertionState.buf.extensions);

			ctap_ret = ctap_extensions_encode_output(
			    &GA.extensions, getAssertionState.buf.extensions,
			    &ext_encoder_buf_size);
			ctap_check_retr(ctap_ret);
			if (ext_encoder_buf_size) {
				getAssertionState.buf.authData.flags |=
				    (1 << 7);
				auth_data_buf_sz += ext_encoder_buf_size;
			}
		}
	}

	ctap_ret = ctap_get_assertion_cbor_encode_assertion_response(
	    &map, cred, (uint8_t *)&getAssertionState.buf, auth_data_buf_sz,
	    GA.clientDataHash); // 1,2,3,4
	ctap_check_retr(ctap_ret);

	if (validCredCount > 1) {
		cbor_ret = cbor_encode_int(&map, GA_Resp_numberOfCredentials);
		cbor_check_ret(cbor_ret);
		cbor_ret = cbor_encode_int(&map, validCredCount);
		cbor_check_ret(cbor_ret);
	}

	cbor_ret = cbor_encoder_close_container(encoder, &map);
	cbor_check_ret(cbor_ret);

	ctap_ret = save_credential_list(GA.clientDataHash,
					GA.creds + 1 /* skip first credential*/,
					validCredCount - 1, &GA.extensions);
	ctap_check_retr(ctap_ret);

	return (CtapStatus){CTAP2_OK};
}

// adds 2 to map, or 3 if add_user is true
CtapStatus ctap_get_assertion_cbor_encode_assertion_response(
    CborEncoder *map, CTAP_credentialDescriptor *cred, uint8_t *auth_data_buf,
    size_t auth_data_buf_sz, uint8_t *clientDataHash)
{
	CborError cbor_ret;
	CtapStatus ctap_ret;
	uint8_t sigbuf[64];
	uint8_t sigder[72];
	size_t sigder_sz;

	cbor_ret = cbor_encode_int(map, GA_Resp_credential);
	cbor_check_ret(cbor_ret);

	ctap_ret = ctap_cbor_encode_credential_descriptor(
	    map, &cred->credential, cred->type);
	ctap_check_retr(ctap_ret);

	{
		cbor_ret = cbor_encode_int(map, MC_Resp_authData);
		cbor_check_ret(cbor_ret);
		cbor_ret = cbor_encode_byte_string(map, auth_data_buf,
						   auth_data_buf_sz);
		cbor_check_ret(cbor_ret);
	}

	size_t cred_size = ctap_get_credential_id_size((int)(cred->type));
	int32_t cose_alg = ctap_restore_metadata_cose_alg(&cred->credential.id);
	if (cose_alg == COSE_ALG_EDDSA) {
		fido2_crypto_ed25519_load_key((uint8_t *)&cred->credential.id,
					      cred_size);
	} else {
		crypto_ecc256_load_key((uint8_t *)&cred->credential.id,
				       cred_size, NULL, 0);
	}

	{
		sigder_sz =
		    ctap_sign_data(auth_data_buf, auth_data_buf_sz,
				   clientDataHash, sigbuf, sigder, cose_alg);
	}

	printf1(TAG_GREEN, "sigder_sz = %d\n", sigder_sz);

	{
		cbor_ret = cbor_encode_int(map, GA_Resp_signature);
		cbor_check_ret(cbor_ret);
		cbor_ret = cbor_encode_byte_string(map, sigder, sigder_sz);
		cbor_check_ret(cbor_ret);
	}

	if (cred->credential.user.id_size) {
		printf1(TAG_GREEN, "adding user details to output\n");

		cbor_ret = cbor_encode_int(map, GA_Resp_user);
		cbor_check_ret(cbor_ret);

		ctap_ret = ctap_cbor_encode_user_entity(
		    map, &cred->credential.user,
		    getAssertionState.user_verified);
		ctap_check_retr(ctap_ret);
	}

	return (CtapStatus){CTAP2_OK};
}

// @return the number of valid credentials
// sorts the credentials.  Most recent creds will be first, invalid ones
// last.
static size_t build_filtered_credential_list(CTAP_getAssertion *GA,
					     uint8_t *rp_id_hash,
					     uint8_t *rp_id_lookup)
{
	size_t i;
	size_t count = 0;
	CTAP_residentKey rk;

	for (i = 0; i < GA->credLen; i++) {

		CTAP_credentialDescriptor *cred = &GA->creds[i];
		uint8_t is_rk = 0;

		if (!ctap_credential_belongs_to_rp(rp_id_lookup, rp_id_hash,
						   cred)) {
			{

				printf1(TAG_GA,
					"allowList: CRED #%d is invalid\n",
					cred->credential.id.count);

				cred->credential.id.count = 0; // invalidate
			}
			continue;
		}

		int protection_status = ctap_check_credential_metadata(
		    &cred->credential.id, getAssertionState.user_verified, 1,
		    &is_rk);

		if (protection_status != 0) {
			printf1(TAG_GREEN,
				"allowList: skipping protected credential.\n");
			cred->credential.id.count = 0; // invalidate
			continue;
		}

		// If it is discoverable, verify that it still exists -
		// otherwise invalidate
		if (is_rk) {
			if (!ctap_verify_rk_exists(&cred->credential.id)) {
				cred->credential.id.count = 0; // invalidate
				continue;
			}
		}

		count++;
		GA->credLen = i + 1;
	}

	// No allowList, so use all matching RK's matching rpId
	if (!GA->credLen) {

		int nr_rk = ctap_open_rk_file(rp_id_lookup);
		if (nr_rk < 0) {
			printf1(TAG_GREEN, "No file to open: %d\n", nr_rk);
			nr_rk = 0;
		}

		for (i = 0; i < (size_t)nr_rk; i++) {

			ctap_load_next_rk(&rk);

			printf1(TAG_GREEN, "rp_id_lookup %d:\n", i);
			dump_hex1(TAG_GREEN, rk.id.rp_id_lookup,
				  CREDENTIAL_TAG_SIZE);

			if (memcmp(rp_id_lookup, rk.id.rp_id_lookup,
				   CREDENTIAL_TAG_SIZE)) {
				// Not the right RPID
				continue;
			}

			// Verify credential mac
			uint8_t local_tag[16];
			ctap_make_auth_tag(rp_id_lookup, rk.id.nonce,
					   rk.id.protected_metadata,
					   rk.id.count, local_tag);

			if (memcmp(rk.id.tag, local_tag, CREDENTIAL_TAG_SIZE) !=
			    0) {
				printf1(TAG_GREEN,
					"Cred failed mac verification\n");
				continue;
			}

			// Check cred protect
			uint8_t is_rk = 0;
			int protection_status = ctap_check_credential_metadata(
			    &rk.id, getAssertionState.user_verified, 0, &is_rk);

			if (protection_status != 0) {
				printf1(TAG_GREEN,
					"Skipping protected rk credential.\n");
				continue;
			}

			if (count >= ALLOW_LIST_MAX_SIZE) {
				printf2(TAG_ERR,
					"not enough ram allocated for "
					"matching RK's (%d).  "
					"Skipping.\n",
					count);
				break;
			}

			// Verify mac over the residential key.
			if (!ctap_verify_mac(rk.rk_tag, &rk.user,
					     RK_HMAC_SIZE)) {
				printf1(TAG_GREEN,
					"rk failed mac verification\n");
				continue;
			}

			// Decrypt user data in place
			ctap_xcrypt_buf(rk.rk_nonce, &rk.user, &rk.user,
					sizeof(CTAP_userEntity) +
					    sizeof(rpEntity));

			GA->creds[count].type = PUB_KEY_CRED_PUB_KEY;

			memmove(&GA->creds[count].credential.id, &rk.id,
				sizeof(CredentialId));

			// Fill in user as well, needed by RP
			memmove(&GA->creds[count].credential.user, &rk.user,
				sizeof(CTAP_userEntity));

			count++;
		}
		ctap_close_rk_file();
		GA->credLen = count;
	}

	printf1(TAG_GA, "qsort length: %d\n", GA->credLen);
	qsort(GA->creds, GA->credLen, sizeof(CTAP_credentialDescriptor),
	      cred_cmp_func);
	return count;
}

static int cred_cmp_func(const void *_a, const void *_b)
{
	const CTAP_credentialDescriptor *a =
	    (const CTAP_credentialDescriptor *)_a;
	const CTAP_credentialDescriptor *b =
	    (const CTAP_credentialDescriptor *)_b;

	return (b->credential.id.count > a->credential.id.count)   ? 1
	       : (b->credential.id.count < a->credential.id.count) ? -1
								   : 0;
}

static CtapStatus parse_get_assertion_request(CTAP_getAssertion *GA,
					      uint8_t *request, size_t length)
{
	CborError cbor_ret;
	CtapStatus ctap_ret;
	unsigned int i;
	int key;
	size_t map_length;
	CborParser parser;
	CborValue it, map;

	memset(GA, 0, sizeof(CTAP_getAssertion));
	GA->creds = getAssertionState.creds; // Save stack memory
	GA->up = 0xff;			     // Show that it is not present

	cbor_ret = cbor_parser_init(request, length,
				    CborValidateCanonicalFormat, &parser, &it);
	cbor_check_ret(cbor_ret);

	if (cbor_value_get_type(&it) != CborMapType) {
		printf2(TAG_ERR, "Error, expecting cbor map\n");
		return (CtapStatus){CTAP2_ERR_INVALID_CBOR};
	}

	cbor_ret = cbor_value_enter_container(&it, &map);
	cbor_check_ret(cbor_ret);

	cbor_ret = cbor_value_get_map_length(&it, &map_length);
	cbor_check_ret(cbor_ret);

	printf1(TAG_GA, "GA map has %d elements\n", map_length);

	for (i = 0; i < map_length; i++) {
		if (cbor_value_get_type(&map) != CborIntegerType) {
			printf2(TAG_ERR, "Error, expecting int for map key\n");
			return (CtapStatus){CTAP2_ERR_INVALID_CBOR};
		}
		cbor_ret = cbor_value_get_int_checked(&map, &key);
		cbor_check_ret(cbor_ret);

		cbor_ret = cbor_value_advance(&map);
		cbor_check_ret(cbor_ret);
		cbor_ret = CborNoError;

		switch (key) {

		case GA_Cmd_clientDataHash:
			printf1(TAG_GA, "GA_Cmd_clientDataHash\n");

			ctap_ret = ctap_parse_fixed_length_byte_string(
			    &map, GA->clientDataHash, CLIENT_DATA_HASH_SIZE);
			ctap_check_retr(ctap_ret);
			GA->clientDataHashPresent = 1;

			printf1(TAG_GA, "\n");
			dump_hex1(TAG_GA, GA->clientDataHash, 32);
			break;

		case GA_Cmd_rpId:
			printf1(TAG_GA, "GA_Cmd_rpId\n");

			ctap_ret = ctap_parse_rp_id(&GA->rp, &map);
			ctap_check_retr(ctap_ret);

			printf1(TAG_GA, "  ID: %s\n", GA->rp.id);
			break;

		case GA_Cmd_allowList:
			printf1(TAG_GA, "GA_Cmd_allowList\n");
			ctap_ret = parse_allow_list_credentials(GA, &map);
			ctap_check_retr(ctap_ret);
			GA->allowListPresent = 1;
			break;

		case GA_Cmd_extensions:
			printf1(TAG_GA, "GA_Cmd_extensions\n");
			ctap_ret = ctap_extensions_parse_input(
			    &map, &GA->extensions, REQ_TYPE_GA);
			ctap_check_retr(ctap_ret);
			break;

		case GA_Cmd_options:
			printf1(TAG_GA, "GA_Cmd_options\n");
			ctap_ret =
			    ctap_parse_options(&map, &GA->rk, &GA->uv, &GA->up);
			ctap_check_retr(ctap_ret);
			break;

		case GA_Cmd_pinUvAuthParam:
			printf1(TAG_GA, "GA_Cmd_pinUvAuthParam\n");
			ctap_ret = ctap_parse_pinUvAuthParam(
			    &map, &GA->pinUvAuthParam_empty, GA->pinUvAuthParam,
			    &GA->pinUvAuthParam_len);
			ctap_check_retr(ctap_ret);

			break;

		case GA_Cmd_pinUvAuthProtocol:
			printf1(TAG_GA, "GA_Cmd_pinUvAuthProtocol\n");
			if (cbor_value_get_type(&map) != CborIntegerType) {
				return (CtapStatus){CTAP2_ERR_INVALID_CBOR};
			}
			int tmp;
			cbor_ret = cbor_value_get_int_checked(&map, &tmp);
			cbor_check_ret(cbor_ret);
			if (tmp < 0 || tmp > (int)UINT8_MAX) {
				return (CtapStatus){CTAP2_ERR_INVALID_CBOR};
			}
			GA->pinProtocol = (uint8_t)tmp;

			break;
		}

		if (cbor_ret != CborNoError) {
			printf2(TAG_ERR, "Error, parsing failed\n");
			cbor_check_ret(cbor_ret);
		}
		if (ctap_ret.value != CTAP2_OK) {
			printf2(TAG_ERR, "Error, parsing failed\n");
			return ctap_ret;
		}

		cbor_ret = cbor_value_advance(&map);
		cbor_check_ret(cbor_ret);
	}

	return (CtapStatus){CTAP2_OK};
}

static CtapStatus parse_allow_list_credentials(CTAP_getAssertion *GA,
					       CborValue *it)
{
	CborValue arr;
	size_t len;
	CborError cbor_ret;
	CtapStatus ctap_ret;
	unsigned int i;
	CTAP_credentialDescriptor *cred;

	if (cbor_value_get_type(it) != CborArrayType) {
		printf2(TAG_ERR, "Error, expecting cbor array\n");
		return (CtapStatus){CTAP2_ERR_INVALID_CBOR};
	}

	cbor_ret = cbor_value_enter_container(it, &arr);
	cbor_check_ret(cbor_ret);

	cbor_ret = cbor_value_get_array_length(it, &len);
	cbor_check_ret(cbor_ret);

	GA->credLen = 0;

	for (i = 0; i < len; i++) {
		if (i >= ALLOW_LIST_MAX_SIZE) {
			printf1(TAG_PARSE,
				"Error, out of memory for allow list.\n");
			return (CtapStatus){CTAP2_ERR_LIMIT_EXCEEDED};
		}

		GA->credLen += 1;
		cred = &GA->creds[i];

		memset(cred, 0, sizeof(CTAP_credentialDescriptor));
		ctap_ret = ctap_parse_pubkey_credential_descriptor(&arr, cred);
		ctap_check_retr(ctap_ret);

		cbor_ret = cbor_value_advance(&arr);
		cbor_check_ret(cbor_ret);
	}
	return (CtapStatus){CTAP2_OK};
}

static CtapStatus save_credential_list(uint8_t *clientDataHash,
				       CTAP_credentialDescriptor *creds,
				       uint32_t count,
				       CTAP_extensions *extensions)
{
	if (count) {
		if (count > ALLOW_LIST_MAX_SIZE - 1) {
			printf2(TAG_ERR, "ALLOW_LIST_MAX_SIZE Exceeded\n");
			return (CtapStatus){CTAP2_ERR_LIMIT_EXCEEDED};
		}

		memmove(getAssertionState.clientDataHash, clientDataHash,
			CLIENT_DATA_HASH_SIZE);
		memmove(getAssertionState.creds, creds,
			sizeof(CTAP_credentialDescriptor) * (count));
		memmove(&getAssertionState.extensions, extensions,
			sizeof(CTAP_extensions));
	}
	getAssertionState.count = count;
	getAssertionState.index = 0;
	printf1(TAG_GA, "saved %d credentials\n", count);
	return (CtapStatus){CTAP2_OK};
}
