// Copyright 2019 SoloKeys Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include "log.h"
#include "util.h"
#include "device.h"

#if DEBUG_LEVEL > 0

static uint32_t LOGMASK = TAG_FILENO;
uint32_t fido2_log_profile_indent_level = 0;

void set_logging_mask(uint32_t mask)
{
    LOGMASK = mask;
}


struct logtag
{
    uint32_t tagn;
    const char * tag;
};

struct logtag tagtable[] = {
    {TAG_GEN,""},
    {TAG_MC,"MC"},
    {TAG_GA,"GA"},
    {TAG_CP,"CP"},
    {TAG_ERR,"ERR"},
    {TAG_PARSE,"PARSE"},
    {TAG_CTAP,"CTAP"},
    {TAG_U2F,"U2F"},
    {TAG_DUMP,"DUMP"},
    {TAG_DUMP2,"DUMP2"},
    {TAG_HID,"HID"},
    {TAG_USB,"USB"},
    {TAG_GREEN,"[1;32mDEBUG[0m"},
    {TAG_RED,"[1;31mDEBUG[0m"},
    {TAG_TIME,"[1;33mTIME[0m"},
    {TAG_WALLET,"[1;34mWALLET[0m"},
    {TAG_STOR,"[1;35mSTOR[0m"},
    {TAG_BOOT,"[1;36mBOOT[0m"},
    {TAG_EXT,"[1;37mEXT[0m"},
    {TAG_NFC,"[1;38mNFC[0m"},
    {TAG_NFC_APDU, "NAPDU"},
    {TAG_CCID, "CCID"},
    {TAG_CM, "CRED_MGMT"},
    {TAG_PROF, "PROF"},
};


__attribute__((weak)) void set_logging_tag(uint32_t tag)
{
    // nothing
}

void LOG(uint32_t tag, const char * filename, int num, const char * fmt, ...)
{
    unsigned int i;

    if (((tag & 0x7fffffff) & LOGMASK) == 0)
    {
        return;
    }
    for (i = 0; i < sizeof(tagtable)/sizeof(struct logtag); i++)
    {
        if (tag & tagtable[i].tagn)
        {
            if (tagtable[i].tag[0] && !(tag & TAG_NO_TAG)) printf("[%s] ", tagtable[i].tag);
            i = 0;
            break;
        }
    }
    if (i != 0)
    {
        printf2(TAG_ERR,"INVALID LOG TAG\n");
        exit(1);
    }
    set_logging_tag(tag);
#ifdef ENABLE_FILE_LOGGING
    if (tag & TAG_FILENO)
    {
        printf("%s:%d: ", filename, num);
    }
#endif
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
}

void LOG_HEX(uint32_t tag, uint8_t * data, int length)
{
    if (((tag & 0x7fffffff) & LOGMASK) == 0)
    {
        return;
    }
    set_logging_tag(tag);
    dump_hex(data,length);
}

uint32_t timestamp()
{
    static uint32_t t1 = 0;
    uint32_t t2 = millis();
    uint32_t diff = t2 - t1;
    t1 = t2;
    return diff;
}

void LOG_PROFILE(const char *msg, uint8_t indent_level, uint32_t duration_ms, const char *filename, uint32_t start_line, uint32_t end_line) {
    char indent[16];
    if (indent_level > (sizeof(indent) - 1)) {
        LOG(TAG_PROF, NULL, 0, "CALL STACK TOO DEEP!\r\n");
    }
    for (uint8_t i = 0; i < indent_level; i++) {
        indent[i] = ' ';
    }
    indent[indent_level] = '\0';

    LOG(TAG_PROF, NULL, 0, "%s+ %6u ms, %s, %s:%d-%d\r\n",
        indent,
        duration_ms,
        msg,
        filename,
        start_line,
        end_line);
}

#endif
