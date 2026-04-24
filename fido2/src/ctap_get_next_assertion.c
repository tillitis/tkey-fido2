#include <stdint.h>

#include "ctap.h"
#include "ctap_errors.h"
#include "ctap_get_assertion.h"
#include "ctap_get_next_assertion.h"
#include "ctap_parse.h"
#include "log.h"

extern struct _getAssertionState getAssertionState;

static CTAP_credentialDescriptor *get_next_credential();

uint8_t ctap_get_next_assertion(CborEncoder *encoder)
{
	int ret;
	CborEncoder map;

	CTAP_credentialDescriptor *cred = get_next_credential();

	if (cred == NULL) {
		return CTAP2_ERR_NOT_ALLOWED;
	}

	printf1(TAG_GREEN, "NextAssertion: Cred count %d\n",
		cred->credential.id.count);

	ctap_auth_data_update_count(&getAssertionState.buf.authData);
	// TODO: Is this move necessary? Should already be there, and
	// not change.
	// memmove(getAssertionState.buf.authData.rpIdHash,
	// 	cred->credential.id.rpIdHash, 32);

	if (cred->credential.user.id_size) {
		printf1(TAG_GREEN,
			"adding user info to assertion response\r\n");
		ret = cbor_encoder_create_map(encoder, &map, 4);
	} else {
		printf1(TAG_GREEN,
			"NOT adding user info to assertion response\r\n");
		ret = cbor_encoder_create_map(encoder, &map, 3);
	}

	check_ret(ret);

	// if only one account for this RP, null out the user details
	if (!getAssertionState.user_verified) {
		printf1(
		    TAG_GREEN,
		    "Not verified, nulling out user details on response\r\n");
		memset(cred->credential.user.name, 0, USER_NAME_LIMIT);
	}

	unsigned int ext_encoder_buf_size =
	    sizeof(getAssertionState.buf.extensions);
	ret = ctap_extensions_encode_output(&getAssertionState.extensions,
					    getAssertionState.buf.extensions,
					    &ext_encoder_buf_size);

	if (ret == 0) {
		if (ext_encoder_buf_size) {
			getAssertionState.buf.authData.flags |= (1 << 7);
		} else {
			getAssertionState.buf.authData.flags &= ~(1 << 7);
		}
	}

	ret = ctap_get_assertion_cbor_encode_assertion_response(
	    &map, cred, (uint8_t *)&getAssertionState.buf.authData,
	    sizeof(CTAP_authDataHeader) + ext_encoder_buf_size,
	    getAssertionState.clientDataHash);

	check_retr(ret);

	ret = cbor_encoder_close_container(encoder, &map);
	check_ret(ret);

	return 0;
}

static CTAP_credentialDescriptor *get_next_credential()
{
	if (getAssertionState.count > 0 &&
	    getAssertionState.index < getAssertionState.count) {
		return &getAssertionState.creds[getAssertionState.index++];
	} else {
		return NULL;
	}
}
