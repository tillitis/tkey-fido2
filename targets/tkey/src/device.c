// SPDX-FileCopyrightText: 2019 SoloKeys Developers
// SPDX-FileCopyrightText: 2024 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: Apache-2.0 OR MIT

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "device.h"
#include "storage.h"

#include APP_CONFIG
#include "assert.h"
#include "ctap.h"
#include "ctaphid.h"
#include "device.h"
#include "fifo.h"
#include "frame.h"
#include "init.h"
#include "log.h"
#include "memory_layout.h"
#include "rng.h"
#include "timer.h"
#include "tkey/io.h"
#include "tkey/led.h"
#include "tkey/tk1_mem.h"

#include "fs.h"
#include "printf-emb.h"

// clang-format off
static volatile uint32_t *timer = (volatile uint32_t *)TK1_MMIO_TIMER_TIMER;
static volatile uint32_t *touch = (volatile uint32_t *)TK1_MMIO_TOUCH_STATUS;
// clang-format on

#define HID_PACKET_SIZE 64

uint32_t __device_status = 0;
static bool _up_disabled = false;

static fs_file_t _f_rk = {0};

void device_disable_up(bool disable)
{
	_up_disabled = disable;
}

uint32_t millis(void)
{
	uint32_t timer_val = *timer;
	if (timer_val <= 1) {
		assert(1 == 2);
	}
	return TIMER_MAX - timer_val;
}

void device_set_status(uint32_t status)
{
	if (status != CTAPHID_STATUS_IDLE && __device_status != status) {
		ctaphid_update_status(status);
	}
	__device_status = status;
}

void delay(uint32_t ms)
{
	uint32_t time = millis();
	while ((millis() - time) < ms)
		;
}

void device_reboot(void)
{
	printf1(TAG_ERR, "Tried to reboot TKey");
	assert(1 == 2);
}

void device_init()
{
	hw_init();
	// usbhid_init();
	ctaphid_init();
	ctap_init();

	// For now make make sure the folder RK exists.
	fs_create_dir("rk");
}

void usbhid_init(void)
{
}

int usbhid_recv(uint8_t *msg)
{
	if (fifo_hidmsg_size()) {
		fifo_hidmsg_take(msg);
		printf1(TAG_DUMP2, ">>\n");
		dump_hex1(TAG_DUMP2, msg, HID_PACKET_SIZE);
		return HID_PACKET_SIZE;
	}
	return 0;
}

void usbhid_send(uint8_t *msg)
{
	printf1(TAG_DUMP2, "<<\n");
	dump_hex1(TAG_DUMP2, msg, HID_PACKET_SIZE);
	write(IO_FIDO, msg, HID_PACKET_SIZE);
}

void usbhid_close(void)
{
	// TKey USB cannot be closed
	assert(1 == 2);
}

void device_wink(void)
{
	for (uint8_t i = 0; i < 2; i++) {
		led_set(LED_GREEN);
		delay(300);
		led_set(LED_BLACK);
		delay(300);
	}
}

int authenticator_read_state(AuthenticatorState *a)
{
	if (fs_read_open("state", a, sizeof(AuthenticatorState), 0) <= 0) {
		// Either new file (read size 0) or error.
		return 0;
	}

	if (a->is_initialized != INITIALIZED_MARKER) {
		return 0;
	}

	return 1;
}

void authenticator_write_state(AuthenticatorState *a)
{
	fs_write_open("state", a, sizeof(AuthenticatorState), 0);
}

uint32_t ctap_atomic_count(uint32_t amount)
{

	fs_file_t f = {0x00};
	fs_open_file(&f, "counter", LFS_O_RDWR | LFS_O_CREAT);

	uint32_t lastc = 0;
	int ret = fs_read(&f, &lastc, sizeof(lastc));

	printf2(TAG_COUNT, "read count (ret: %d) %lu\r\n", ret, lastc);

	if (ret < 0) {
		lastc = 0;
	}

	if (amount == 0) {
		// Use a random count [1-16].
		uint8_t rng[1];
		ctap_generate_rng(rng, 1);
		amount = (rng[0] & 0x0f) + 1;
	}

	lastc += amount;

	fs_write_at(&f, &lastc, sizeof(lastc), 0);
	fs_close_file(&f);

	printf2(TAG_COUNT, "returning count: %lu\r\n", lastc);
	return lastc;
}

int ctap_user_presence_test(uint32_t up_delay)
{
	if (_up_disabled) {
		return 2;
	}

	uint32_t start_time = millis();
	uint32_t time;
	bool led_on;

#ifdef AUTO_TOUCH
	return 1;
#endif

	*touch = 0;
	do {
		if (*touch & (1 << TK1_MMIO_TOUCH_STATUS_EVENT_BIT)) {
			led_set(LED_GREEN | LED_RED);
			return 1;
		}

		time = millis();
		led_on = ((time - start_time) / 100 % 2);
		led_set(led_on ? LED_GREEN : LED_BLACK);
	} while ((time - start_time) < up_delay);

	led_set(LED_BLACK);

	return 0;
}

int ctap_generate_rng(uint8_t *dst, size_t num)
{
	if (rng_get_bytes(dst, num)) {
		return 0; // Error
	}
	return 1; // success
}

void ctap_reset_rk(void)
{
	printf1(TAG_GREEN, "resetting RK \r\n");
	fs_dir_del("rk");
}

uint32_t ctap_rk_size(void)
{
	// return RK_NUM_PAGES * (PAGE_SIZE / sizeof(CTAP_residentKey));
	return 200;
}

static void rpid_hash_to_file(char *out, size_t out_len, const uint8_t *hash)
{
	uint8_t file_name = hash[0] >> 4; // 0x0–0xf
	snprintf(out, out_len, "rk/%x.dat", file_name);
}

int ctap_store_rk(const CTAP_residentKey *rk)
{
	char path[16]; // "rk/x.dat"
	fs_file_t f = {0};
	int ret;

	rpid_hash_to_file(path, sizeof(path), rk->id.rpIdHash);

	ret = fs_open_file(&f, path, LFS_O_RDWR | LFS_O_CREAT | LFS_O_APPEND);
	if (ret < 0) {
		return ret;
	}

	printf1(TAG_GREEN, "ctap_store_rk: (%s)\r\n", path);
	dump_hex1(TAG_GREEN, rk->id.rpIdHash, 32);
	// Append rk to the end
	ret = fs_write(&f, rk, sizeof(CTAP_residentKey));
	fs_close_file(&f);

	return ret;
}

int ctap_delete_rk(CredentialId *id)
{
	CTAP_residentKey rk;
	char path[16]; // "rk/x.dat"
	fs_file_t f = {0};
	int ret;

	rpid_hash_to_file(path, sizeof(path), id->rpIdHash);

	ret = fs_open_file(&f, path, LFS_O_RDWR);
	if (ret < 0) {
		printf1(TAG_GREEN, "delete rk: No file to open: %d \r\n", ret);
		return -1;
	}

	int count = fs_file_size(&f);
	if (count <= 0) {
		return -1;
	}
	// Calculate number of credentials stored
	count = count / sizeof(CTAP_residentKey);

	for (uint16_t i = 0; i < count; i++) {

		// read next rk
		fs_read(&f, &rk, sizeof(CTAP_residentKey));
		if (memcmp(id->rpIdHash, rk.id.rpIdHash, 32)) {
			// Not the right RPID
			continue;
		}

		// The tag is unique
		if (memcmp(id->tag, &rk.id.tag, sizeof(id->tag)) == 0) {
			printf1(TAG_GREEN, "delete rk: found match (%d)\r\n",
				i);

			// re-write file without this key to avoid gaps
			CTAP_residentKey temp_rks[10];
			int remaining =
			    count - (i + 1); // keys after the one to delete
			int processed = 0;

			while (remaining > 0) {
				int to_read = remaining;
				if (to_read > 10)
					to_read = 10;

				// Read from position i+1+processed
				ret = fs_read_at(&f, temp_rks,
						 to_read *
						     sizeof(CTAP_residentKey),
						 (i + 1 + processed) *
						     sizeof(CTAP_residentKey));
				if (ret <= 0) {
					printf1(
					    TAG_GREEN,
					    "delete rk: read error (%d)\r\n",
					    ret);
					fs_close_file(&f);
					return -1;
				}

				// Write back at position i + processed
				ret = fs_write_at(&f, temp_rks, ret,
						  (i + processed) *
						      sizeof(CTAP_residentKey));
				if (ret <= 0) {
					printf1(
					    TAG_GREEN,
					    "delete rk: write error (%d)\r\n",
					    ret);
					fs_close_file(&f);
					return -1;
				}

				processed += to_read;
				remaining -= to_read;
			}

			// Truncate the file at the new size
			fs_truncate_file(&f, (count - 1) *
						 sizeof(CTAP_residentKey));
			fs_close_file(&f);
			break;
		}
	}
	return 0;
}

// Opens the file where the RP should exist. Returns number of keys stored in
// the file. Returns negative on error.
int ctap_open_rk_file(uint8_t rpid_hash[32])
{

	char path[16]; // "rk/x.dat"
	int ret;

	rpid_hash_to_file(path, sizeof(path), rpid_hash);

	ret = fs_open_file(&_f_rk, path, LFS_O_RDONLY);
	if (ret < 0) {
		return -1;
	}

	ret = fs_file_size(&_f_rk);
	// Calculate number of credentials stored
	ret = ret / sizeof(CTAP_residentKey);
	printf1(TAG_GREEN, "ctap_open_rk_file: %d (%s)\r\n", ret, path);
	return ret;
}

int ctap_close_rk_file(void)
{
	printf1(TAG_GREEN, "ctap_close_rk_file\r\n");
	return fs_close_file(&_f_rk);
}

void ctap_load_next_rk(CTAP_residentKey *dst_rk)
{
	// should return error, and size maybe
	fs_read(&_f_rk, dst_rk, sizeof(CTAP_residentKey));

	printf1(TAG_GREEN, "Load next RK\r\n");
}

void ctap_load_rk(int index, CTAP_residentKey *dst_rk)
{
	fs_read_at(&_f_rk, dst_rk, sizeof(CTAP_residentKey),
		   index * sizeof(CTAP_residentKey));

	printf1(TAG_GREEN, "Load RK: %d\r\n", index);
}

void ctap_overwrite_rk(int index, CTAP_residentKey *rk)
{
	printf1(TAG_GREEN, "overwrite rk: \r\n");

	ctap_store_rk(rk);
	return;
}

void device_read_aaguid(uint8_t *dst)
{
	uint8_t *aaguid = (uint8_t *)"\xdb\xe4\x2d\x66\x22\xbe\x46\x24\x88\x11"
				     "\x97\x2a\x8e\x65\x36\x7e";
	memmove(dst, aaguid, 16);
	dump_hex1(TAG_GREEN, dst, 16);
}
