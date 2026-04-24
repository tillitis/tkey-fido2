// SPDX-FileCopyrightText: 2019 SoloKeys Developers
// SPDX-License-Identifier: Apache-2.0 OR MIT

#ifndef _CTAP_CLIENT_PIN_H_
#define _CTAP_CLIENT_PIN_H_

#include <stdint.h>
#include <stdlib.h>

#include "cbor.h"
#include "cose_key.h"

// clang-format off
#define NEW_PIN_ENC_MAX_SIZE 256 // Includes NULL terminator
#define NEW_PIN_ENC_MIN_SIZE 64
#define NEW_PIN_MAX_SIZE     64
#define NEW_PIN_MIN_SIZE     4

#define PIN_LOCKOUT_ATTEMPTS 8 // Number of attempts total
#define PIN_BOOT_ATTEMPTS    3 // Number of attempts per boot

#define PIN_TOKEN_SIZE 16

// clang-format on

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

uint8_t ctap_client_pin(CborEncoder *encoder, uint8_t *request, int length);
uint8_t ctap_client_pin_decrement_attempts();
int8_t ctap_client_pin_is_boot_locked();
int8_t ctap_client_pin_is_locked();
uint8_t ctap_client_pin_is_set();
void ctap_client_pin_reset_attempts();
uint8_t ctap_client_pin_verify_auth(uint8_t *pinAuth, uint8_t *clientDataHash);
uint8_t ctap_client_pin_verify_auth_ex(uint8_t *pinAuth, uint8_t *buf,
				       size_t len);

#endif
