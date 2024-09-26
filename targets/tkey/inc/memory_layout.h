// Copyright 2019 SoloKeys Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
#ifndef _MEMORY_LAYOUT_H_
#define _MEMORY_LAYOUT_H_

#define PAGE_SIZE		2048
#define PAGES			128

// Location of counter page and it's backup page
// The flash is wear leveled and counter should be fault tolerant
#define	COUNTER2_PAGE	(PAGES - 4)
#define	COUNTER1_PAGE	(PAGES - 3)

// State of FIDO2 application
#define	STATE2_PAGE		      (PAGES - 2)
#define	STATE1_PAGE		      (PAGES - 1)

// Storage of FIDO2 resident keys
#define RK_NUM_PAGES    10
#define RK_START_PAGE   (PAGES - 14)
#define RK_END_PAGE     (PAGES - 14 + RK_NUM_PAGES)     // not included

// where attestation key is located
#define ATTESTATION_PAGE        (PAGES - 15)
#define ATTESTATION_PAGE_ADDR   (0x08000000 + ATTESTATION_PAGE*PAGE_SIZE)

#include <assert.h>

#define ATTESTATION_CONFIGURED_TAG      0xaa551e79

struct flash_attestation_page{
  uint8_t attestation_key[32];
  // DWORD padded.
  uint64_t device_settings;
  uint64_t attestation_cert_size;
  uint8_t attestation_cert[2048 - 32 - 8 - 8];
} __attribute__((packed));

typedef struct flash_attestation_page flash_attestation_page;

static_assert(sizeof(flash_attestation_page) == 2048, "Data structure doesn't match flash size");


#endif
