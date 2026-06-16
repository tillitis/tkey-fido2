// SPDX-FileCopyrightText: 2019 SoloKeys Developers
// SPDX-FileCopyrightText: 2024 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: Apache-2.0 OR MIT

#include <stdbool.h>
#include <stdint.h>

#include "ctaphid.h"
#include "fifo.h"
#include "log.h"

#include "frame.h"
#include "tkey/debug.h"
#include "tkey/led.h"
#include "tkey/proto.h"
#include "tkey/syscall.h"
#include "tkey/tk1_mem.h"

#define HID_PACKET_SIZE 64
#define CMD_RESET 0xFE

// clang-format off
//static volatile uint32_t *cdi           = (volatile uint32_t *) TK1_MMIO_TK1_CDI_FIRST;
static volatile uint32_t *cpu_mon_ctrl  = (volatile uint32_t *) TK1_MMIO_TK1_CPU_MON_CTRL;
static volatile uint32_t *cpu_mon_first = (volatile uint32_t *) TK1_MMIO_TK1_CPU_MON_FIRST;
static volatile uint32_t *cpu_mon_last  = (volatile uint32_t *) TK1_MMIO_TK1_CPU_MON_LAST;
static volatile uint32_t *app_addr      = (volatile uint32_t *) TK1_MMIO_TK1_APP_ADDR;
static volatile uint32_t *app_size      = (volatile uint32_t *) TK1_MMIO_TK1_APP_SIZE;
// clang-format on

static void appreply_nok(struct frame_header hdr);
static uint8_t genhdr(uint8_t id, uint8_t endpoint, uint8_t status,
		      enum frame_cmdlen len);
static void reset(uint8_t reset_type, uint8_t boot_verifier_action);

int main(void)
{
	uint8_t hidmsg[HID_PACKET_SIZE];
	uint8_t data[HID_PACKET_SIZE];

	// Use Execution Monitor on RAM after app
	*cpu_mon_first = *app_addr + *app_size;
	*cpu_mon_last = TK1_RAM_BASE + TK1_RAM_SIZE;
	*cpu_mon_ctrl = 1;

	led_set(LED_BLUE);

	// clang-format off
	set_logging_mask(
	    // TAG_GEN |
	    // TAG_MC |
	    // TAG_GA |
	    // TAG_STOR |
	    // TAG_CP |
	    // TAG_CTAP |
	    // TAG_HID |
	    // TAG_U2F |
	    // TAG_PARSE |
	    // TAG_TIME |
	    // TAG_DUMP |
	    // TAG_GREEN |
	    // TAG_RED |
	    // TAG_EXT |
	    // TAG_CCID |
	    // TAG_COUNT |
	    // TAG_PROF|
	    // TAG_ERR |
	    0);
	// clang-format on

	device_init();

	memset(hidmsg, 0, sizeof(hidmsg));

	while (1) {
		enum ioend ep;
		uint8_t available;

		led_set(LED_BLUE);

		if (readselect(IO_CDC | IO_FIDO, false, &ep, &available) != 0) {
			assert(1 == 2);
		}

		if (ep == IO_CDC) {
			if (available >= 1) {
				uint8_t c;
				bool fail = false;
				read(IO_CDC, &c, 1, 1);
				struct frame_header hdr = {0};
				if (frame_parse_hdr(c, &hdr) != 0) {
					fail = true;
				}

				// Update available bytes
				readselect(IO_CDC, true, &ep, &available);

				// Frame parsing failed, discard and continue
				if (fail) {
					discard(IO_CDC, available);
					continue;
				}

				// Well-behaved apps are supposed to check for a
				// client attempting to probe for firmware. In
				// that case destination is firmware and we just
				// reply NOK, discarding all bytes already read.
				if (hdr.f_domain == DST_FW) {
					appreply_nok(hdr);
					debug_puts("Responded NOK to message "
						   "meant for FW\n");
					discard(IO_CDC, available);
					continue;
				}

				// Is it for us? If not, continue after having
				// discarded all bytes.
				if (hdr.f_domain != DST_SW) {
					debug_puts("Message not meant for app. "
						   "Endpoint was 0x");
					debug_puthex((uint8_t)hdr.f_domain);
					debug_lf();
					discard(IO_CDC, available);
					continue;
				}

				// For now, only accept a command of length 4
				// (reset command)
				if ((hdr.len != 4) || (available != 4)) {
					discard(IO_CDC, available);
					continue;
				}

				uint8_t buf[available];
				memset(buf, 0, available);

				read(IO_CDC, buf, available, available);
				switch (buf[0]) {
				case CMD_RESET:
					reset(buf[1], buf[2]);
					break;
				default:
					continue;
					break;
				}
				printf2(TAG_ERR, "Device not reset\n");
				while (1)
					;
			}
		}

		if (available != HID_PACKET_SIZE) {
			// Discard data
			printf2(TAG_ERR,
				"Got incomplete HID frame, discard.\n");
			read(IO_FIDO, data, sizeof(data), available);
			continue;
		}

		if (read(IO_FIDO, data, sizeof(data), available) !=
		    HID_PACKET_SIZE) {
			assert(1 == 2);
		}

		if (fifo_hidmsg_add(data) != 0) {
			return -1;
		}

		if (usbhid_recv(hidmsg) > 0) {
			led_set(LED_GREEN | LED_RED);
			ctaphid_handle_packet(hidmsg);
			memset(hidmsg, 0, sizeof(hidmsg));
		} else {
		}

		ctaphid_check_timeouts();
	}

	// Should never get here
	usbhid_close();
	printf1(TAG_GREEN, "done\n");
	assert(1 == 2);
	return 0;
}

// Send reply frame with response status Not OK (NOK==1), shortest length
static void appreply_nok(struct frame_header hdr)
{
	uint8_t buf[2];
	enum ioend dst = IO_CDC;

	buf[0] = genhdr(hdr.id, (uint8_t)hdr.f_domain, 0x1, LEN_1);
	buf[1] = 0; // Not used, but smallest payload is 1 byte

	write(dst, buf, 2);
}

static uint8_t genhdr(uint8_t id, uint8_t endpoint, uint8_t status,
		      enum frame_cmdlen len)
{
	return (uint8_t)((id << 5) | (endpoint << 3) | (status << 2) |
			 (uint8_t)len);
}

static void reset(uint8_t reset_type, uint8_t boot_verifier_action)
{
	struct reset rst = {0};
	rst.type = reset_type;
	rst.next_app_data[0] = boot_verifier_action;

	sys_reset(&rst, 1);
}
