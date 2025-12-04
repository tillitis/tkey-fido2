// SPDX-FileCopyrightText: 2019 SoloKeys Developers
// SPDX-License-Identifier: Apache-2.0 OR MIT

#ifndef _FLASH_H_
#define _FLASH_H_

#include <stddef.h>
#include <stdint.h>

void flash_erase_page(uint8_t page);
void flash_write_dword(uint32_t addr, uint64_t data);
void flash_write(uint32_t addr, uint8_t *data, size_t sz);
void flash_read(uint32_t addr, uint8_t *dst, size_t sz);
int flash_init();

#define FLASH_BASE_ADDRESS 0
#define FLASH_PAGE_SIZE 4096UL

#define flash_addr(page) ((page) * FLASH_PAGE_SIZE)

#endif
