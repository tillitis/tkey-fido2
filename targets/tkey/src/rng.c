// SPDX-FileCopyrightText: 2024 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: Apache-2.0 OR MIT

#include <stddef.h>
#include <stdint.h>
#include <tkey/lib.h>
#include <tkey/tk1_mem.h>

#include "../../../fido2/crypto.h"
#include "rng.h"

// clang-format off
static volatile	uint32_t *cdi =          (volatile uint32_t *)TK1_MMIO_TK1_CDI_FIRST;
static volatile uint32_t *trng_status =  (volatile uint32_t *)TK1_MMIO_TRNG_STATUS;
static volatile uint32_t *trng_entropy = (volatile uint32_t *)TK1_MMIO_TRNG_ENTROPY;
// clang-format on

#define RESEED_TIME 4096

typedef struct {
	uint32_t state_ctr_lsb;
	uint32_t state_ctr_msb;
	uint32_t reseed_ctr;
	uint32_t state[16];
	uint32_t digest[8];
} rng_ctx;

static rng_ctx ctx;
static uint8_t rng_initialized = 0;

static uint32_t entropy_get()
{
	while ((*trng_status & (1 << TK1_MMIO_TRNG_STATUS_READY_BIT)) == 0) {
	}
	return *trng_entropy;
}

static void rng_update(rng_ctx *ctx)
{
	for (size_t i = 0; i < 8; i++) {
		ctx->state[i] = ctx->digest[i];
	}

	ctx->state_ctr_lsb += 1;
	if (ctx->state_ctr_lsb == 0) {
		ctx->state_ctr_msb += 1;
	}
	ctx->state[14] += ctx->state_ctr_msb;
	ctx->state[15] += ctx->state_ctr_lsb;

	ctx->reseed_ctr += 1;
	if (ctx->reseed_ctr == RESEED_TIME) {
		for (size_t i = 0; i < 8; i++) {
			ctx->state[i + 8] = entropy_get();
		}
		ctx->reseed_ctr = 0;
	}
}

void rng_init(void)
{

	for (size_t i = 0; i < 8; i++) {
		ctx.state[i] = cdi[i] + entropy_get();
		ctx.state[i + 8] = entropy_get();
	}

	ctx.state_ctr_lsb = entropy_get();
	ctx.state_ctr_msb = entropy_get();

	ctx.reseed_ctr = 0;

	// Perform initial mixing of state.
	crypto_sha256((uint8_t *)ctx.digest, (uint8_t *)ctx.state, 64);
	rng_update(&ctx);

	rng_initialized = 1;
}

// Generate sz bytes of random data and put it in dst. Returns zero on success
int rng_get_bytes(uint8_t *dst, size_t sz)
{

	if (rng_initialized == 0) {
		return -1;
	}

	size_t dst_index = 0;

	while (dst_index < sz) {
		// Generate data and update state
		crypto_sha256((uint8_t *)ctx.digest, (uint8_t *)ctx.state, 64);
		rng_update(&ctx);

		// Only use the first 16 bytes of digest, the rest is used to
		// generate the next state
		for (size_t i = 0; i < 16; i++) {

			dst[dst_index++] = (uint8_t)ctx.digest[i];

			if (dst_index >= sz) {
				break;
			}
		}
	}
	return 0;
}

void randombytes(uint8_t *dst, size_t sz)
{
	rng_get_bytes(dst, sz);
}
