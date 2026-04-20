// SPDX-FileCopyrightText: 2019 SoloKeys Developers
// SPDX-License-Identifier: Apache-2.0 OR MIT

#ifndef _CTAP_EXTENTIONS_H_
#define _CTAP_EXTENTIONS_H_

#include <stdint.h>

#include "cbor.h"
#include "cose_key.h"
#include "ctap.h"

typedef struct {
	uint8_t saltLen;
	uint8_t saltEnc[64];
	uint8_t saltAuth[32];
	COSE_key keyAgreement;
	struct Credential *credential;
} CTAP_hmac_secret;

typedef struct {
	uint8_t hmac_secret_present;
	CTAP_hmac_secret hmac_secret;
	uint8_t cred_protect;
} CTAP_extensions;

int ctap_make_extensions(CTAP_extensions *ext, uint8_t *ext_encoder_buf,
			 unsigned int *ext_encoder_buf_size);
uint8_t ctap_parse_extensions(CborValue *val, CTAP_extensions *ext);
uint8_t ctap_parse_hmac_secret(CborValue *val, CTAP_hmac_secret *hs);

#endif
