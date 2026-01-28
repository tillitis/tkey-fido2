// SPDX-FileCopyrightText: 2024 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: Apache-2.0 OR MIT

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "flash.h"

#ifdef USE_OLD_STORAGE_TYPE

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

#endif
