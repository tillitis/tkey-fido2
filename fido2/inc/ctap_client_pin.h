// SPDX-FileCopyrightText: 2019 SoloKeys Developers
// SPDX-License-Identifier: Apache-2.0 OR MIT

#ifndef _CTAP_CLIENT_PIN_H_
#define _CTAP_CLIENT_PIN_H_

#include <stdint.h>
#include <stdlib.h>

#include "cbor.h"
#include "cose_key.h"

#define NEW_PIN_ENC_MAX_SIZE 256 // Includes NULL terminator

typedef struct {
	int pinProtocol;
	int subCommand;
	COSE_key keyAgreement;
	uint8_t keyAgreementPresent;
	uint8_t pinAuth[16];
	uint8_t pinAuthPresent;
	uint8_t newPinEnc[NEW_PIN_ENC_MAX_SIZE];
	int newPinEncSize;
	uint8_t pinHashEnc[16];
	uint8_t pinHashEncPresent;
	_Bool getKeyAgreement;
	_Bool getRetries;
} CTAP_clientPin;

uint8_t ctap_add_pin_if_verified(uint8_t *pinTokenEnc, uint8_t *platform_pubkey,
				 uint8_t *pinHashEnc);
uint8_t ctap_client_pin(CborEncoder *encoder, uint8_t *request, int length);
uint8_t ctap_parse_client_pin(CTAP_clientPin *CP, uint8_t *request, int length);
void ctap_reset_pin_attempts();
uint8_t ctap_update_pin_if_verified(uint8_t *pinEnc, int len,
				    uint8_t *platform_pubkey, uint8_t *pinAuth,
				    uint8_t *pinHashEnc);
void ctap_update_pin(uint8_t *pin, int len);
int trailing_zeros(uint8_t *buf, int indx);

#endif
