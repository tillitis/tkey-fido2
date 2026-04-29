// SPDX-FileCopyrightText: 2019 SoloKeys Developers
// SPDX-FileCopyrightText: 2026 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: Apache-2.0 OR MIT

#ifndef _CTAP_CREDENTIAL_MANAGEMENT_H_
#define _CTAP_CREDENTIAL_MANAGEMENT_H_

#include <stdint.h>

#include "cbor.h"
#include "ctap.h"

typedef struct {
	int subCommand;
	struct {
		uint8_t rpIdHash[32];
		CTAP_credentialDescriptor credentialDescriptor;
	} subCommandParams;

	struct {
		uint8_t subCommand;
		uint8_t
		    subCommandParamsCborCopy[sizeof(CTAP_credentialDescriptor) +
					     16];
	} hashed;
	uint32_t subCommandParamsCborSize;

	uint8_t pinAuth[16];
	uint8_t pinAuthPresent;
	int pinProtocol;
} CTAP_credMgmt;

uint8_t ctap_credential_management(CborEncoder *encoder, uint8_t *request,
				   int length);

#endif
