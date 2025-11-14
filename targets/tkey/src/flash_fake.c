// Copyright 2024 Tillitis AB
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "flash.h"

__attribute__((
    __aligned__(4))) volatile static uint8_t fake_flash[6 * FLASH_PAGE_SIZE];

uint32_t flash_addr(uint32_t page)
{
	uint32_t addr = (uint32_t)(fake_flash + page * FLASH_PAGE_SIZE);
	return addr;
}

void flash_erase_page(uint8_t page)
{
	memset((uint8_t *)fake_flash + page * FLASH_PAGE_SIZE, 0xff,
	       FLASH_PAGE_SIZE);
}

void flash_write_dword(uint32_t addr, uint64_t data)
{
	memcpy((uint8_t *)addr, &data, sizeof(data));
}

void flash_write(uint32_t addr, uint8_t *data, size_t sz)
{
	memmove((uint8_t *)addr, data, sz);
}
