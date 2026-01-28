// SPDX-FileCopyrightText: 2019 SoloKeys Developers
// SPDX-License-Identifier: Apache-2.0 OR MIT

#ifndef _MEMORY_LAYOUT_H_
#define _MEMORY_LAYOUT_H_

#include "flash.h"
#include <stdint.h>

#ifdef USE_OLD_STORAGE_TYPE

#define FLASH_BASE_ADDRESS 0
#define PAGE_SIZE 4096
#define PAGES (128 * 1024 / PAGE_SIZE) // 32 pages, numbered 0-31

// Location of counter page and it's backup page
// The flash is wear leveled and counter should be fault tolerant
#define COUNTER2_PAGE (PAGES - 4) // Page 28
#define COUNTER1_PAGE (PAGES - 3) // Page 29

// State of FIDO2 application
#define STATE2_PAGE (PAGES - 2) // Page 30
#define STATE1_PAGE (PAGES - 1) // Page 31

// Storage of FIDO2 resident keys
#define RK_NUM_PAGES 27
#define RK_START_PAGE (PAGES - 31)		// Page 1
#define RK_END_PAGE (PAGES - 31 + RK_NUM_PAGES) // Page 28, not included

// where attestation key is located
#define ATTESTATION_PAGE (PAGES - 32) // Page 0
#define ATTESTATION_PAGE_ADDR                                                  \
	(FLASH_BASE_ADDRESS + ATTESTATION_PAGE * PAGE_SIZE)

#include <assert.h>

#define ATTESTATION_CONFIGURED_TAG 0xaa551e79

#endif

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
