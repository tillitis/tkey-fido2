// SPDX-FileCopyrightText: 2019 SoloKeys Developers
// SPDX-FileCopyrightText: 2024 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: Apache-2.0 OR MIT

#include <stdbool.h>
#include <stdint.h>

#include "ctaphid.h"
#include "fifo.h"
#include "log.h"
#include APP_CONFIG

#include "frame.h"
#include "tkey/debug.h"
#include "tkey/led.h"
#include "tkey/proto.h"
#include "tkey/syscall.h"
#include "tkey/tk1_mem.h"

#define HID_PACKET_SIZE 64

// clang-format off
//static volatile uint32_t *cdi           = (volatile uint32_t *) TK1_MMIO_TK1_CDI_FIRST;
static volatile uint32_t *cpu_mon_ctrl  = (volatile uint32_t *) TK1_MMIO_TK1_CPU_MON_CTRL;
static volatile uint32_t *cpu_mon_first = (volatile uint32_t *) TK1_MMIO_TK1_CPU_MON_FIRST;
static volatile uint32_t *cpu_mon_last  = (volatile uint32_t *) TK1_MMIO_TK1_CPU_MON_LAST;
static volatile uint32_t *app_addr      = (volatile uint32_t *) TK1_MMIO_TK1_APP_ADDR;
static volatile uint32_t *app_size      = (volatile uint32_t *) TK1_MMIO_TK1_APP_SIZE;
// clang-format on

#ifndef USE_OLD_STORAGE_TYPE

#include "lfs.h"

// Flash parameters
#define LFS_READ_SIZE        256
#define LFS_PROG_SIZE        256
#define LFS_BLOCK_SIZE       4096
#define LFS_BLOCK_COUNT      32
#define LFS_CACHE_SIZE       256
#define LFS_LOOKAHEAD_SIZE   16

//#define WRITE_ALIGNMENT      256

// Static memory
static uint8_t read_buffer[LFS_CACHE_SIZE] = {0};
static uint8_t prog_buffer[LFS_CACHE_SIZE] = {0};
static uint8_t lookahead_buffer[LFS_LOOKAHEAD_SIZE] = {0};

//static uint8_t write_buf[WRITE_ALIGNMENT] = {0};

// Flash I/O callbacks
int lfs_read_wrapper(const struct lfs_config *c,
		lfs_block_t block,
		lfs_off_t off,
		void *buffer,
		lfs_size_t size)
{
	uint32_t abs_offset = block * c->block_size + off;
	int ret = sys_read(abs_offset, buffer, size);
	if (ret < 0) return ret;  // map your error to negative
	return 0;                 // success
}

int lfs_prog_wrapper(const struct lfs_config *c, lfs_block_t block,
		lfs_off_t off, const void *buffer, lfs_size_t size) {
	uint32_t abs_offset = (block * c->block_size) + off;

	// Safety check for 128KB limit
	if (abs_offset + size > 128 * 1024)
		return LFS_ERR_NOSPC;

	// With prog_size=256, off is always % 256 == 0 and size is always % 256 == 0
	if (sys_write(abs_offset, (void*) buffer, size) != 0) {
		return LFS_ERR_IO;
	}
	return LFS_ERR_OK;
}

int lfs_erase_wrapper(const struct lfs_config *c,
		lfs_block_t block)
{
	uint32_t abs_offset = block * c->block_size;

	// Must erase multiples of 4096 bytes
	if (c->block_size % 4096 != 0)
		return -1;  // unsupported configuration

	int ret = sys_erase(abs_offset, c->block_size);
	return (ret < 0) ? -1 : 0;
}

int lfs_sync_wrapper(const struct lfs_config *c) {
	(void)c;  // unused
	return 0;
}

// Config
const struct lfs_config cfg = {
		// block device operations
		.read  = lfs_read_wrapper,
		.prog  = lfs_prog_wrapper,
		.erase = lfs_erase_wrapper,
		.sync  = lfs_sync_wrapper,

		// block device configuration
		.read_size = LFS_READ_SIZE,
		.prog_size = LFS_PROG_SIZE,
		.block_size = LFS_BLOCK_SIZE,
		.block_count = LFS_BLOCK_COUNT,

		.cache_size = LFS_CACHE_SIZE,
		.lookahead_size = LFS_LOOKAHEAD_SIZE,

		.read_buffer = read_buffer,
		.prog_buffer = prog_buffer,
		.lookahead_buffer = lookahead_buffer,

		// Number of erase cycles before littlefs evicts metadata logs and moves
		// the metadata to another block. Suggested values are in the
		// range 100-1000, with large values having better performance at the cost
		// of less consistent wear distribution.
		.block_cycles = 500,
};

lfs_t lfs  = {0};
lfs_file_t file = {0};
struct lfs_file_config config = {0};
uint8_t g_file_buf[LFS_CACHE_SIZE];

#endif

int main()
{
	uint8_t hidmsg[HID_PACKET_SIZE];
	uint8_t data[HID_PACKET_SIZE];

	// Use Execution Monitor on RAM after app
	*cpu_mon_first = *app_addr + *app_size;
	*cpu_mon_last = TK1_RAM_BASE + TK1_RAM_SIZE;
	*cpu_mon_ctrl = 1;

	led_set(LED_BLUE);

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
	    // TAG_ERR |
	    0);

	device_init();

	memset(hidmsg, 0, sizeof(hidmsg));

	while (1) {
		enum ioend ep;
		uint8_t available;

		led_set(LED_BLUE);

		if (readselect(IO_CDC | IO_FIDO, &ep, &available) != 0) {
			assert(1 == 2);
		}

		if (ep == IO_CDC) {
			uint8_t b;
			read(IO_CDC, &b, sizeof(b), 1);
			struct reset rst = {0};
			rst.type = b - '0' + START_DEFAULT;
			sys_reset(&rst, 0);
			printf2(TAG_ERR, "Device not reset\r\n");
			while (1)
				;
		}

		if (available != HID_PACKET_SIZE) {
			// Discard data
			printf2(TAG_ERR,
				"Got incomplete HID frame, discard\r\n");
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
