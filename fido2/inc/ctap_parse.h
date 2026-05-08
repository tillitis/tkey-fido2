// SPDX-FileCopyrightText: 2019 SoloKeys Developers
// SPDX-FileCopyrightText: 2026 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: Apache-2.0 OR MIT

#ifndef _CTAP_PARSE_H_
#define _CTAP_PARSE_H_

#include <stdint.h>

#include "cbor.h"
#include "ctap.h"
#include "ctap_errors.h"

#define check_ret(r)                                                           \
	_check_ret(r, __LINE__, __FILE__);                                     \
	if ((r) != CborNoError)                                                \
		return CTAP2_ERR_INVALID_CBOR;

#define check_retr(r)                                                          \
	_check_ret(r, __LINE__, __FILE__);                                     \
	if ((r) != CborNoError)                                                \
		return r;

extern void _check_ret(CborError ret, int line, const char *filename);

const char *cbor_value_get_type_string(const CborValue *value);
uint8_t ctap_parse_fixed_length_byte_string(CborValue *map, uint8_t *dst,
					    unsigned int len);
uint8_t ctap_parse_options(CborValue *val, uint8_t *rk, uint8_t *uv,
			   uint8_t *up);
uint8_t
ctap_parse_pubkey_credential_descriptor(CborValue *arr,
					CTAP_credentialDescriptor *cred);
uint8_t ctap_parse_rp_id(struct rpId *rp, CborValue *val);
uint8_t ctap_parse_user_entity(CTAP_userEntity *user, CborValue *val);

#endif
