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

#define FLASH_BASE_ADDRESS  0
#define FLASH_PAGE_SIZE     2048

uint32_t flash_addr(uint32_t page);

#endif
