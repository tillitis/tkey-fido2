// SPDX-FileCopyrightText: 2024 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: Apache-2.0 OR MIT

#include <stdint.h>
#include <tkey/assert.h>
#include <tkey/io.h>
#include <tkey/tk1_mem.h>

#include APP_CONFIG
#include "flash.h"
#include "init.h"
#include "rng.h"
#include "timer.h"

// clang-format off
static volatile uint32_t *timer =           (volatile uint32_t *)TK1_MMIO_TIMER_TIMER;
static volatile uint32_t *timer_prescaler = (volatile uint32_t *)TK1_MMIO_TIMER_PRESCALER;
static volatile uint32_t *timer_ctrl =      (volatile uint32_t *)TK1_MMIO_TIMER_CTRL;
// clang-format on
#define CPUFREQ 24000000

void hw_init()
{
	init_millisecond_timer();
	init_usb();
	rng_init();

	if (flash_init() != 0) {
		assert(1 == 2);
	}
}

void init_millisecond_timer()
{
	*timer_prescaler =
	    CPUFREQ / 1000; // Divide CPUFREQ by 1000 to get 1 tick every ms.
	*timer = TIMER_MAX;
	*timer_ctrl = (1 << TK1_MMIO_TIMER_CTRL_START_BIT);
}

void init_usb(void)
{
	enum ioend eps = IO_CDC | IO_FIDO;

#ifdef TKEY_DEBUG
	eps |= IO_DEBUG;
#endif

	config_endpoints(eps);
}
