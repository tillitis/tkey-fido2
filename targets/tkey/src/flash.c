// Copyright 2019 SoloKeys Developers
// Copyright 2025 Tillitis AB
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <tkey/assert.h>
#include <tkey/syscall.h>

#include "log.h"
#include "flash.h"

#define WRITE_SIZE 256

const uint32_t WRITE_ALIGN_MASK = (~(WRITE_SIZE - 1));

void flash_erase_page(uint8_t page)
{
    int ret = 0;
    uint32_t addr = page * FLASH_PAGE_SIZE;

    ret = sys_erase(addr, FLASH_PAGE_SIZE);
    if(ret != 0)
    {
        printf2(TAG_ERR,"erase NOT successful addr=%lx, len=%lx, ret=%lx\r\n", addr, FLASH_PAGE_SIZE, ret);
    }
}

void flash_write_dword(uint32_t addr, uint64_t data)
{
    flash_write(addr, (uint8_t*)&data, 2);
}

void flash_write(uint32_t addr, uint8_t * data, size_t sz)
{
    uint8_t buf[WRITE_SIZE];

    uint32_t buf_offset = addr & ~WRITE_ALIGN_MASK;
    size_t len = 0;

    printf2(TAG_GREEN,"flash write addr=%lx, size=%lx\r\n", addr, sz);

    for(size_t i = 0; i < sz; i += len)
    {
        size_t bytes_left = sz - i;
        size_t dst_max_len = WRITE_SIZE - buf_offset;
        size_t src_max_len = bytes_left < WRITE_SIZE ? bytes_left : WRITE_SIZE;
        len = src_max_len < dst_max_len ? src_max_len : dst_max_len;

        memset(buf, 0xff, sizeof(buf));
        memcpy(buf + buf_offset, data + i, len);

        int ret = sys_write(addr & WRITE_ALIGN_MASK, buf, WRITE_SIZE);
        if (ret != 0) {
            printf2(TAG_ERR,"flash write NOT successful addr=%lx, ret=%lx\r\n", addr, ret);
        }

        buf_offset = 0;
        addr += len;
    }
}

void flash_read(uint32_t addr, uint8_t * dst, size_t sz)
{
    int ret = 0;

    printf2(TAG_GREEN,"flash read addr=%lx, size=%lx\r\n", addr, sz);
    ret = sys_read(addr, dst, sz);
    if (ret != 0) {
        printf2(TAG_ERR,"flash read NOT successful addr=%lx, len=%lx, ret=%lx\r\n", addr, sz, ret);
    }
}

int flash_init()
{
    int ret = 0;

    ret = sys_alloc();
    if (ret != 0) {
        printf2(TAG_ERR,"flash alloc NOT successful %lx\r\n", ret);
    }

    return ret;
}
