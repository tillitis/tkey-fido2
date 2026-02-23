// SPDX-FileCopyrightText: 2019 SoloKeys Developers
// SPDX-License-Identifier: Apache-2.0 OR MIT

#ifndef _MEMORY_LAYOUT_H_
#define _MEMORY_LAYOUT_H_

#include <assert.h>
#include <stdint.h>

#define ATTESTATION_CONFIGURED_TAG 0xaa551e79

struct flash_attestation_page {
	uint8_t attestation_key[32];
	// DWORD padded.
	uint64_t device_settings;
	uint64_t attestation_cert_size;
	uint8_t attestation_cert[2048 - 32 - 8 - 8];
} __attribute__((packed));

typedef struct flash_attestation_page flash_attestation_page;

static_assert(sizeof(flash_attestation_page) == 2048,
	      "Data structure doesn't match flash size");

#endif
