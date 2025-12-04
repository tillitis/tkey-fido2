// SPDX-FileCopyrightText: 2019 SoloKeys Developers
// SPDX-FileCopyrightText: 2025 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: Apache-2.0 OR MIT

#ifndef _RNG_H_
#define _RNG_H_

#include <stddef.h>
#include <stdint.h>

void rng_init(void);
int rng_get_bytes(uint8_t *dst, size_t sz);

#endif
