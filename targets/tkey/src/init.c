// Copyright 2019 SoloKeys Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
#include <stdint.h>

#include "init.h"
#include APP_CONFIG

#include "tkey/io.h"
#include "tkey/tk1_mem.h"
#include "timer.h"

static volatile uint32_t *timer             = (volatile uint32_t *)TK1_MMIO_TIMER_TIMER;
static volatile uint32_t *timer_prescaler   = (volatile uint32_t *)TK1_MMIO_TIMER_PRESCALER;
static volatile uint32_t *timer_ctrl        = (volatile uint32_t *)TK1_MMIO_TIMER_CTRL;
#define CPUFREQ 24000000

void hw_init()
{
    init_millisecond_timer();
    init_rng();
    init_usb();
}

void init_millisecond_timer()
{
    *timer_prescaler = CPUFREQ / 1000; // Divide CPUFREQ by 1000 to get 1 tick every ms.
    *timer = TIMER_MAX;
    *timer_ctrl = (1 << TK1_MMIO_TIMER_CTRL_START_BIT);
}

void init_rng(void)
{
}

void init_usb(void)
{
    enum ioend eps = IO_CDC | IO_FIDO;

#ifdef TKEY_DEBUG
    eps |= IO_DEBUG;
#endif

    config_endpoints(eps);
}
