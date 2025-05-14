// Copyright 2019 SoloKeys Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
#ifndef _FLASH_H_
#define _FLASH_H_

#include <stdint.h>
#include <stddef.h>

void flash_erase_page(uint8_t page);
void flash_write_dword(uint32_t addr, uint64_t data);
void flash_write(uint32_t addr, uint8_t * data, size_t sz);
void flash_read(uint32_t addr, uint8_t * dst, size_t sz);
int flash_init();

#define FLASH_BASE_ADDRESS  0
#define FLASH_PAGE_SIZE     4096UL

#define flash_addr(page)    ((page)*FLASH_PAGE_SIZE)

#endif
