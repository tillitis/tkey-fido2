// SPDX-FileCopyrightText: 2019 SoloKeys Developers
// SPDX-FileCopyrightText: 2024 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: Apache-2.0 OR MIT

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "assert.h"
#include "cbor.h"
#include "crypto.h"
#include "ctap.h"
#include "ctaphid.h"
#include "device.h"
#include "fifo.h"
#include "fs.h"
#include "init.h"
#include "log.h"
#include "printf-emb.h"
#include "rng.h"
#include "state.h"
#include "timer.h"
#include "tkey/io.h"
#include "tkey/led.h"
#include "tkey/tk1_mem.h"

// clang-format off
static volatile uint32_t *timer = (volatile uint32_t *)TK1_MMIO_TIMER_TIMER;
static volatile uint32_t *touch = (volatile uint32_t *)TK1_MMIO_TOUCH_STATUS;
static volatile uint32_t const *cdi   = (volatile uint32_t *)TK1_MMIO_TK1_CDI_FIRST;
// clang-format on

#define HID_PACKET_SIZE 64

uint8_t __device_status = 0;
static bool _up_disabled = false;

static fs_file_t _f_rk = {0};

const uint8_t *device_get_bound_secret(void)
{
	return (const uint8_t *)cdi;
}

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

void device_set_status(uint8_t status)
{
	if (status != CTAPHID_STATUS_IDLE) {
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

// Initializes the device
// Returns zero on success.
// On error it returns:
// 2: file system corrupted and non-recoverable
// 3: app is not allowed to start, wrong version
uint8_t device_init(void)
{
	hw_init();
	ctaphid_init();

	// fs_init should come before ctap_init
	if (fs_init() != 0) {
		return 2;
	}

	if (ctap_init() < 0) {
		return 3;
	}

	// For now make make sure the folder RK exists.
	if (fs_create_dir("rk")) {
		return 2;
	}
	return 0;
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
	uint8_t tmp_buf[STATE_ENVELOPE_BUF_SIZE];
	uint8_t *magic = tmp_buf;
	uint8_t *mac = tmp_buf + STATE_MAGIC_SIZE;
	uint8_t *cbor = mac + STATE_MAC_SIZE;

	int ret = fs_read_open("state", tmp_buf, sizeof(tmp_buf));
	if (ret <= 0) {
		// Either new file (read size 0) or error.
		return 0;
	}

	// The envelope for the state is [magic(1)][mac(16)][cbor]
	// Check magic
	if (*magic != STATE_MAGIC) {
		printf1(TAG_ERR, "auth_read_state: magic failed\n");
		return 0;
	}
	// Validate mac
	size_t cbor_size = (size_t)ret - STATE_MAGIC_SIZE - STATE_MAC_SIZE;

	if (!crypto_verify_device_mac(cbor, cbor_size, mac, STATE_MAC_SIZE)) {
		printf1(TAG_ERR, "auth_read_state: mac failed\n");
		return 0;
	}

	// Deserialize
	if (state_cbor_decode(a, cbor, cbor_size) != 0) {
		printf1(TAG_ERR, "auth_read_state: deserialize failed\n");
		return 0;
	}
	return 1;
}

void authenticator_write_state(AuthenticatorState *a)
{
	// The envelope for the state is [magic(1)][mac(16)][cbor]
	uint8_t write_buf[STATE_ENVELOPE_BUF_SIZE] = {0};
	uint8_t *magic = write_buf;
	uint8_t *mac = write_buf + STATE_MAGIC_SIZE;
	uint8_t *cbor = mac + STATE_MAC_SIZE;

	*magic = STATE_MAGIC;

	size_t cbor_max_size =
	    sizeof(write_buf) - STATE_MAGIC_SIZE - STATE_MAC_SIZE;

	size_t cbor_size;
	CborError cbor_ret =
	    state_cbor_encode(cbor, cbor_max_size, a, &cbor_size);
	if (cbor_ret != CborNoError) {
		assert(1 == 2);
	}

	crypto_compute_device_mac(cbor, cbor_size, mac, STATE_MAC_SIZE);

	size_t write_size = cbor_size + STATE_MAGIC_SIZE + STATE_MAC_SIZE;
	int ret = fs_write_open("state", write_buf, write_size);
	if (ret != write_size) {
		assert(1 == 2);
	}
}

uint32_t ctap_atomic_count(uint32_t amount)
{

	fs_file_t f = {0x00};
	fs_open_file(&f, "counter", LFS_O_RDWR | LFS_O_CREAT);

	uint32_t lastc = 0;
	int ret = fs_read(&f, &lastc, sizeof(lastc));

	printf2(TAG_COUNT, "read count (ret: %d) %lu\n", ret, lastc);

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

	printf2(TAG_COUNT, "returning count: %lu\n", lastc);
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
			led_set(LED_BLACK);
			device_set_status(CTAPHID_STATUS_PROCESSING);

			return 1;
		}

		device_set_status(CTAPHID_STATUS_UPNEEDED);

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
	printf1(TAG_GREEN, "Resetting RK\n");
	fs_dir_del("rk");
}

uint32_t ctap_max_number_of_rks(void)
{
	return 200;
}

// Returns the path to the file, based on hash.
// Supports a hash that is only one byte long.
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

	rpid_hash_to_file(path, sizeof(path), rk->id.rp_id_lookup);

	ret = fs_open_file(&f, path, LFS_O_RDWR | LFS_O_CREAT | LFS_O_APPEND);
	if (ret < 0) {
		return ret;
	}

	printf1(TAG_GREEN, "ctap_store_rk: (%s)\n", path);
	dump_hex1(TAG_GREEN, rk->id.rp_id_lookup, CREDENTIAL_TAG_SIZE);
	// Append rk to the end
	ret = fs_write(&f, rk, sizeof(CTAP_residentKey));
	if (ret <= 0) {
		printf2(TAG_ERR, "write error (%d)\n", ret);
		fs_close_file(&f);
		return -1;
	}

	fs_close_file(&f);
	ctap_increment_rk_store();

	return 0;
}

// Overwrites RK if another one with the same rk_id_lookup and user_id_lookup
// exists. Otherwise appends it. Returns zero on success, negative on error.
int ctap_overwrite_rk(const CTAP_residentKey *rk)
{
	int ret;

	printf1(TAG_GREEN, "ctap_overwrite_rk\n");
	dump_hex1(TAG_GREEN, rk->id.rp_id_lookup, CREDENTIAL_TAG_SIZE);

	ret = ctap_open_rk_file(rk->id.rp_id_lookup);

	if (ret < 0) {
		ctap_close_rk_file();
		return -1;
	}

	size_t count = (size_t)ret;
	CTAP_residentKey read_rk;
	size_t offset = 0;

	for (uint16_t i = 0; i < count; i++) {

		// read next rk
		ret = fs_read(&_f_rk, &read_rk, sizeof(CTAP_residentKey));
		if (ret <= 0) {
			printf2(TAG_ERR, "overwrite rk: read error (%d)\n",
				ret);
			ctap_close_rk_file();
			return -1;
		}

		if (memcmp(read_rk.id.rp_id_lookup, rk->id.rp_id_lookup,
			   CREDENTIAL_TAG_SIZE)) {
			// Not the right RPID
			continue;
		}

		if (memcmp(read_rk.user_id_lookup, rk->user_id_lookup,
			   CREDENTIAL_TAG_SIZE)) {
			// Not the right user ID
			continue;
		}

		// Match, write at current position - sizeof(CTAP_residentKey)
		offset = i * sizeof(CTAP_residentKey);
		printf1(TAG_GREEN, "ctap_overwrite_rk: overwritten (%d)\n", i);

		ret = fs_write_at(&_f_rk, rk, sizeof(CTAP_residentKey), offset);
		if (ret <= 0) {
			printf2(TAG_ERR, "write error (%d)\n", ret);
			ctap_close_rk_file();
			return -1;
		}
		ctap_close_rk_file();
		return 0;
	}

	// Only reachead if no match was found, or count = 0
	// Append rk to the end
	printf1(TAG_GREEN, "ctap_overwrite_rk: appended\n");
	offset = count * sizeof(CTAP_residentKey);
	ret = fs_write_at(&_f_rk, rk, sizeof(CTAP_residentKey), offset);
	if (ret <= 0) {
		printf2(TAG_ERR, "write error (%d)\n", ret);
		ctap_close_rk_file();
		return -1;
	}

	ctap_close_rk_file();
	ctap_increment_rk_store();
	return 0;
}

int ctap_delete_rk(CredentialId *id)
{
	CTAP_residentKey rk;
	int ret;

	ret = ctap_open_rk_file(id->rp_id_lookup);

	if (ret <= 0) {
		printf1(TAG_GREEN, "delete rk: No file to open: %d\n", ret);
		ctap_close_rk_file();
		return -1;
	}

	size_t count = (size_t)ret;
	for (size_t i = 0; i < count; i++) {

		// read next rk
		ret = fs_read(&_f_rk, &rk, sizeof(CTAP_residentKey));
		if (ret <= 0) {
			printf2(TAG_ERR, "read error (%d)\n", ret);
			ctap_close_rk_file();
			return -1;
		}

		if (memcmp(id->rp_id_lookup, rk.id.rp_id_lookup,
			   CREDENTIAL_TAG_SIZE)) {
			// Not the right RPID
			continue;
		}

		// The tag is unique
		if (memcmp(id->tag, &rk.id.tag, sizeof(id->tag)) != 0) {
			continue;
		}

		printf1(TAG_GREEN, "delete rk: found match (%d)\n", i);

		// re-write file without this key to avoid gaps
		CTAP_residentKey temp_rks[10];
		size_t remaining =
		    count - (i + 1); // keys after the one to delete
		size_t processed = 0;

		while (remaining > 0) {
			size_t to_read = remaining;
			if (to_read > 10)
				to_read = 10;

			// Read from position i+1+processed
			ret = fs_read_at(&_f_rk, temp_rks,
					 to_read * sizeof(CTAP_residentKey),
					 (i + 1 + processed) *
					     sizeof(CTAP_residentKey));
			if (ret <= 0) {
				printf2(TAG_ERR, "read error (%d)\n", ret);
				ctap_close_rk_file();
				return -1;
			}

			// Write back at position i + processed
			ret = fs_write_at(&_f_rk, temp_rks, (size_t)ret,
					  (i + processed) *
					      sizeof(CTAP_residentKey));
			if (ret <= 0) {
				printf2(TAG_GREEN,
					"delete rk: write error (%d)\n", ret);
				ctap_close_rk_file();
				return -1;
			}

			processed += to_read;
			remaining -= to_read;
		}

		// Truncate the file at the new size
		ret = fs_truncate_file(&_f_rk,
				       (count - 1) * sizeof(CTAP_residentKey));
		if (ret < 0) {
			printf2(TAG_ERR, "truncate file error (%d)\n", ret);
			ctap_close_rk_file();
			return -1;
		}

		ctap_close_rk_file();
		ctap_decrement_rk_store();
		return 0;
	}
	ctap_close_rk_file();
	return -1;
}

// Opens the file where the RP should exist. Returns number of keys stored in
// the file. Returns negative on error.
// Supports that rpid_hash is only one byte long.
int ctap_open_rk_file(const uint8_t *rpid_hash)
{

	char path[16]; // "rk/x.dat"
	int ret;

	rpid_hash_to_file(path, sizeof(path), rpid_hash);

	ret = fs_open_file(&_f_rk, path, LFS_O_RDWR | LFS_O_CREAT);
	if (ret < 0) {
		return -1;
	}

	ret = fs_file_size(&_f_rk);
	if (ret < 0) {
		return -1;
	}
	// Calculate number of credentials stored
	ret = ret / (int)sizeof(CTAP_residentKey);
	printf1(TAG_GREEN, "ctap_open_rk_file: %d (%s)\n", ret, path);
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

	printf1(TAG_GREEN, "Load next RK\n");
}

void ctap_load_rk(uint8_t index, CTAP_residentKey *dst_rk)
{
	fs_read_at(&_f_rk, dst_rk, sizeof(CTAP_residentKey),
		   (size_t)index * sizeof(CTAP_residentKey));

	printf1(TAG_GREEN, "Load RK: %d\n", index);
}
