// SPDX-FileCopyrightText: 2024 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: Apache-2.0 OR MIT

#include "tkey/debug.h"
#include <assert.h>
#include <stdint.h>
#include <tkey/io.h>
#include <tkey/tk1_mem.h>

#include "init.h"
#include "rng.h"
#include "timer.h"

// clang-format off
static volatile uint32_t *timer =           (volatile uint32_t *)TK1_MMIO_TIMER_TIMER;
static volatile uint32_t *timer_prescaler = (volatile uint32_t *)TK1_MMIO_TIMER_PRESCALER;
static volatile uint32_t *timer_ctrl =      (volatile uint32_t *)TK1_MMIO_TIMER_CTRL;
// clang-format on
#define CPUFREQ 24000000

#ifdef TKEY_DEBUG
static uint32_t millis(void)
{
	uint32_t timer_val = *timer;
	if (timer_val <= 1) {
		assert(1 == 2);
	}
	return TIMER_MAX - timer_val;
}

static void delay(uint32_t ms)
{
	uint32_t time = millis();
	while ((millis() - time) < ms)
		;
}
#endif

void hw_init(void)
{
	init_millisecond_timer();
#ifndef QEMU_DEBUG
	init_usb();
#endif
#ifdef TKEY_DEBUG
	delay(2000);
#endif
	rng_init();
}

void init_millisecond_timer(void)
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
