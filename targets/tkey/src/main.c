// SPDX-FileCopyrightText: 2019 SoloKeys Developers
// SPDX-FileCopyrightText: 2024 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: Apache-2.0 OR MIT

#include <stdbool.h>
#include <stdint.h>

#include "ctaphid.h"
#include "fifo.h"
#include "log.h"

#include "tkey/debug.h"
#include "tkey/led.h"
#include "tkey/proto.h"
#include "tkey/syscall.h"
#include "tkey/tk1_mem.h"

#define HID_PACKET_SIZE 64
#define CMD_RESET 0xFE
#define FLASH_ERROR_DELAY_MS 500

// clang-format off
//static volatile uint32_t *cdi           = (volatile uint32_t *) TK1_MMIO_TK1_CDI_FIRST;
static volatile uint32_t *cpu_mon_ctrl  = (volatile uint32_t *) TK1_MMIO_TK1_CPU_MON_CTRL;
static volatile uint32_t *cpu_mon_first = (volatile uint32_t *) TK1_MMIO_TK1_CPU_MON_FIRST;
static volatile uint32_t *cpu_mon_last  = (volatile uint32_t *) TK1_MMIO_TK1_CPU_MON_LAST;
static volatile uint32_t *app_addr      = (volatile uint32_t *) TK1_MMIO_TK1_APP_ADDR;
static volatile uint32_t *app_size      = (volatile uint32_t *) TK1_MMIO_TK1_APP_SIZE;
// clang-format on

static void appreply_nok(struct frame_header hdr);
static void reset(uint32_t type, uint8_t next_app_data[126],
		  uint8_t next_app_len);
static void error_signal_and_exit_app(uint8_t err);
static int cdc_handle_frame(uint8_t *available, enum ioend *ep);

int main(void)
{
	uint8_t hidmsg[HID_PACKET_SIZE];
	uint8_t data[HID_PACKET_SIZE];

	// Use Execution Monitor on RAM after app
	*cpu_mon_first = *app_addr + *app_size;
	*cpu_mon_last = TK1_RAM_BASE + TK1_RAM_SIZE;
	*cpu_mon_ctrl = 1;

	led_set(LED_BLACK);

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

	uint8_t err = device_init();
	if (err != 0) {
		error_signal_and_exit_app(err);
	}

	memset(hidmsg, 0, sizeof(hidmsg));

	while (1) {
		enum ioend ep;
		uint8_t available;

		if (readselect(IO_CDC | IO_FIDO, true, &ep, &available) != 0) {
			assert(1 == 2);
		}

		if (available == 0) {
			continue;
		}

		if (ep == IO_CDC) {
			int ret = cdc_handle_frame(&available, &ep);
			if (ret < 0) {
				discard(IO_CDC, available);
				continue;
			}
		}

		if (ep == IO_FIDO) {
			if (available != HID_PACKET_SIZE) {
				// Discard data
				printf2(TAG_ERR, "Got incomplete HID "
						 "frame, discard.\n");
				discard(IO_FIDO, available);
				continue;
			}

			if (read(IO_FIDO, data, sizeof(data), available) !=
			    HID_PACKET_SIZE) {
				assert(1 == 2);
			}

			if (fifo_hidmsg_add(data) != 0) {
				assert(1 == 2);
			}
		}

		if (usbhid_recv(hidmsg) > 0) {
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

static int cdc_handle_frame(uint8_t *available, enum ioend *ep)
{

	uint8_t c;
	bool fail = false;
	read(IO_CDC, &c, 1, 1);
	struct frame_header hdr = {0};
	if (frame_parse_hdr(c, &hdr) != 0) {
		fail = true;
	}

	// Update available bytes
	readselect(IO_CDC, true, ep, available);

	// Frame parsing failed, discard and continue
	if (fail) {
		return -1;
	}
	// Well-behaved apps are supposed to check for a
	// client attempting to probe for firmware. In
	// that case destination is firmware and we just
	// reply NOK, discarding all bytes already read.
	if (hdr.f_domain == DST_FW) {
		appreply_nok(hdr);
		debug_puts("Responded NOK to message "
			   "meant for FW\n");
		return -1;
	}

	// Is it for us? If not, continue after having
	// discarded all bytes.
	if (hdr.f_domain != DST_SW) {
		debug_puts("Message not meant for app. "
			   "Endpoint was 0x");
		debug_puthex((uint8_t)hdr.f_domain);
		debug_lf();
		return -1;
	}

	uint8_t buf[CMDLEN_MAXBYTES] = {0};

	for (uint8_t n = 0; n < hdr.len;) {
		if (readselect(IO_CDC, false, ep, available) < 0) {
			return -1;
		}

		// Read as much as is available of what we expect from
		// the frame.
		*available = *available > (hdr.len - n) ? ((uint8_t)hdr.len - n)
							: *available;

		int nbytes =
		    read(IO_CDC, &buf[n], CMDLEN_MAXBYTES - n, *available);
		if (nbytes < 0) {
			return -1;
		}

		n += nbytes;
	}

	switch (buf[0]) {
	case CMD_RESET:
		if (hdr.len != 128) {
			return -1;
		}
		reset(buf[1], buf + 2, (uint8_t)hdr.len - 2);

		// Should not be reached
		assert(1 == 2);
		break;
	default:
		// Unknown command, respond with NOK.
		appreply_nok(hdr);
		break;
	}
	return 0;
}

// Send reply frame with response status Not OK (NOK==1), shortest length
static void appreply_nok(struct frame_header hdr)
{
	uint8_t buf[2];
	enum ioend dst = IO_CDC;

	frame_gen_hdr(hdr.id, (uint8_t)hdr.f_domain, FRAME_STATUS_NOK, 1,
		      &buf[0]);
	buf[1] = 0; // Not used, but smallest payload is 1 byte

	write(dst, buf, sizeof(buf));
}

static void reset(uint32_t type, uint8_t next_app_data[126],
		  uint8_t next_app_len)
{

	struct reset rst = {0};
	rst.type = type;
	memcpy(rst.next_app_data, next_app_data, next_app_len);

	sys_reset(&rst, next_app_len);
}

// Signals the error by flashing the LED the number of times as the error value.
// Then resets into the boot verifier command mode.
static void error_signal_and_exit_app(uint8_t err)
{
	for (uint8_t i = 0; i < err; i++) {
		led_set(LED_RED);
		delay(FLASH_ERROR_DELAY_MS);
		led_set(LED_BLACK);
		delay(FLASH_ERROR_DELAY_MS);
	}
	// Keep debug output after blink to increase the chance that the
	// USB-controller is ready
	printf2(TAG_ERR, "device_init failed (%d)\n", err);
	delay(200);
	uint8_t buf = 1;
	reset(START_FLASH0, &buf, sizeof(buf));
}
