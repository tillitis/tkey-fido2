// SPDX-FileCopyrightText: 2019 SoloKeys Developers
// SPDX-FileCopyrightText: 2026 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: Apache-2.0 OR MIT

#ifndef _CTAP_EXTENTIONS_H_
#define _CTAP_EXTENTIONS_H_

#include <stdint.h>

#include "cbor.h"
#include "cose_key.h"

#define EXT_HMAC_SECRET_COSE_KEY 0x01
#define EXT_HMAC_SECRET_SALT_ENC 0x02
#define EXT_HMAC_SECRET_SALT_AUTH 0x03

#define EXT_HMAC_SECRET_REQUESTED 0x01
#define EXT_HMAC_SECRET_PARSED 0x02

#define EXT_CRED_PROTECT_INVALID 0x00
#define EXT_CRED_PROTECT_OPTIONAL 0x01
#define EXT_CRED_PROTECT_OPTIONAL_WITH_CREDID 0x02
#define EXT_CRED_PROTECT_REQUIRED 0x03

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

int ctap_extensions_encode_output(CTAP_extensions *ext,
				  uint8_t *ext_encoder_buf,
				  unsigned int *ext_encoder_buf_size);
uint8_t ctap_extensions_parse_input(CborValue *val, CTAP_extensions *ext);

#endif
