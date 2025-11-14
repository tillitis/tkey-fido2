// Copyright 2024 Tillitis AB
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#include <stddef.h>
#include <stdint.h>

#include "rng.h"
#include "tkey/tk1_mem.h"

// clang-format off
static volatile uint32_t *trng_status =  (volatile uint32_t *)TK1_MMIO_TRNG_STATUS;
static volatile uint32_t *trng_entropy = (volatile uint32_t *)TK1_MMIO_TRNG_ENTROPY;
// clang-format on

void randombytes(uint8_t *dst, size_t sz)
{
	rng_get_bytes(dst, sz);
}

void rng_get_bytes(uint8_t *dst, size_t sz)
{
	for (int i = 0; i < sz; i++) {
		while ((*trng_status & (1 << TK1_MMIO_TRNG_STATUS_READY_BIT)) ==
		       0) {
		}
		dst[i] = (uint8_t)*trng_entropy;
	}
}
