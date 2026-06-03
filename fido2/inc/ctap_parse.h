// SPDX-FileCopyrightText: 2019 SoloKeys Developers
// SPDX-FileCopyrightText: 2026 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: Apache-2.0 OR MIT

#ifndef _CTAP_PARSE_H_
#define _CTAP_PARSE_H_

#include <stdint.h>

#include "cbor.h"
#include "ctap.h"
#include "ctap_errors.h"

/**
 * Check the return value of a CBOR operation.
 *
 * If @p r indicates a failure, logs error (if debug enabled) and returns
 * CTAP2_ERR_INVALID_CBOR from the calling function. Supposed to be used to mask
 * CBOR errors into a CTAP error.
 *
 * @param[in] r Return value from a CBOR operation.
 */
#define cbor_check_ret(r)                                                      \
	if (_cbor_check_ret_failed(r, __LINE__, __FILE__))                     \
		return (CtapStatus){CTAP2_ERR_INVALID_CBOR};

#define cbor_check_retr(r)                                                     \
	if (_cbor_check_ret_failed(r, __LINE__, __FILE__))                     \
		return r;

#define ctap_check_retr(r)                                                     \
	if (_ctap_check_ret_failed(r, __LINE__, __FILE__))                     \
		return r;

extern void _cbor_check_ret(CborError ret, int line, const char *filename);
extern void _ctap_check_ret(CtapStatus ret, int line, const char *filename);

const char *cbor_value_get_type_string(const CborValue *value);
CtapStatus ctap_parse_fixed_length_byte_string(CborValue *map, uint8_t *dst,
					       unsigned int len);
CtapStatus ctap_parse_options(CborValue *val, uint8_t *rk, uint8_t *uv,
			      uint8_t *up);
CtapStatus
ctap_parse_pubkey_credential_descriptor(CborValue *arr,
					CTAP_credentialDescriptor *cred);
CtapStatus ctap_parse_rp_id(struct rpId *rp, CborValue *val);
CtapStatus ctap_parse_user_entity(CTAP_userEntity *user, CborValue *val);

static inline bool _cbor_check_ret_failed(CborError ret, int line,
					  const char *filename)
{
	_cbor_check_ret(ret, line, filename);
	return (ret != CborNoError);
}

static inline bool _ctap_check_ret_failed(CtapStatus ret, int line,
					  const char *filename)
{
	_ctap_check_ret(ret, line, filename);
	return (ret.value != CTAP2_OK);
}

#endif
