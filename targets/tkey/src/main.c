// Copyright 2019 SoloKeys Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
//#include <unistd.h>

#include "cbor.h"
#include "device.h"
#include "ctaphid.h"
//#include "bsp.h"
#include "util.h"
#include "log.h"
#include "ctap.h"
#include "fifo.h"
#include APP_CONFIG

#include "tkey/qemu_debug.h"
#include "tkey/tk1_mem.h"
#include "tkey/led.h"
#include "tkey/proto.h"
#include "frame.h"

// clang-format off
//static volatile uint32_t *cdi           = (volatile uint32_t *) TK1_MMIO_TK1_CDI_FIRST;
static volatile uint32_t *cpu_mon_ctrl  = (volatile uint32_t *) TK1_MMIO_TK1_CPU_MON_CTRL;
static volatile uint32_t *cpu_mon_first = (volatile uint32_t *) TK1_MMIO_TK1_CPU_MON_FIRST;
static volatile uint32_t *cpu_mon_last  = (volatile uint32_t *) TK1_MMIO_TK1_CPU_MON_LAST;
static volatile uint32_t *app_addr      = (volatile uint32_t *) TK1_MMIO_TK1_APP_ADDR;
static volatile uint32_t *app_size      = (volatile uint32_t *) TK1_MMIO_TK1_APP_SIZE;
// clang-format on

// Touch timeout in seconds
#define TOUCH_TIMEOUT 30

uint8_t FrameMode   = 0;
uint8_t FrameLength = 0;


void appreply_cdc_ack(void)
{
    writebyte(MODE_CDC_ACK);
    writebyte(0);
}

void appreply_hid_ack(void)
{
    writebyte(MODE_HID_ACK);
    writebyte(0);
}

static int read_frame(struct header *hdr, uint8_t *data)
{
    memset(hdr, 0, sizeof(struct header));
    memset(data, 0, MAX_FRAME_SIZE);

    hdr->mode = readbyte();
    hdr->len  = readbyte();

    if (hdr->mode == MODE_HID) {
        if (read(data, HID_FRAME_SIZE, hdr->len) != 0) {
            qemu_puts("read: buffer overrun\n");
            return -1;
        }
    }

    return 0;
}

int main()
{
    uint8_t hidmsg[64];
    uint32_t t1 = 0;

    struct frame pkt = {0};

    // Use Execution Monitor on RAM after app
    *cpu_mon_first = *app_addr + *app_size;
    *cpu_mon_last = TK1_RAM_BASE + TK1_RAM_SIZE;
    *cpu_mon_ctrl = 1;

    led_set(LED_BLUE);

    set_logging_mask(
            /*0*/
            //TAG_GEN|
            // TAG_MC |
            // TAG_GA |
            TAG_WALLET |
            TAG_STOR |
            //TAG_CP |
            // TAG_CTAP|
            //TAG_HID|
            TAG_U2F|
            //TAG_PARSE |
            //TAG_TIME|
            // TAG_DUMP|
            TAG_GREEN|
            TAG_RED|
            TAG_EXT|
            TAG_CCID|
            TAG_ERR
    );

    device_init();

    memset(hidmsg,0,sizeof(hidmsg));

    while(1)
    {
        if (read_frame(&pkt.hdr, pkt.data) == 0) {
            if (millis() - t1 > HEARTBEAT_PERIOD) {
                heartbeat();
                t1 = millis();
            }

            device_manage();

            if (fifo_hidmsg_add(pkt.data) != 0) {
                return -1;
            }

            if (usbhid_recv(hidmsg) > 0) {
                ctaphid_handle_packet(hidmsg);
                memset(hidmsg, 0, sizeof(hidmsg));
            } else {
            }
            ctaphid_check_timeouts();
        }
    }

    // Should never get here
    usbhid_close();
    printf1(TAG_GREEN, "done\n");
    return 0;
}
