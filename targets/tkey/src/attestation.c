// SPDX-FileCopyrightText: 2019 SoloKeys Developers
// SPDX-FileCopyrightText: 2024 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: Apache-2.0 OR MIT

#include "crypto.h"
#include "device.h"
#include "fs.h"
#include "log.h"
#include "memory_layout.h"
#include <stdint.h>
#include <string.h>

const uint8_t attestation_key[32] = {0};

// Get size of attestation key in bytes
int device_attestation_get_size_key(uint16_t *size)
{
	int ret = -1;
	fs_file_t f = {0x00};

	ret = fs_open_file(&f, "attestation_key", LFS_O_RDONLY);
	if (ret < 0) {
		return ret;
	}

	ret = fs_file_size(&f);
	fs_close_file(&f);
	if (ret < 0) {
		return ret;
	}

	*size = (uint16_t)ret;

	return 0;
}

int device_attestation_read_key(uint8_t *key_buf, size_t key_buf_size)
{
	int ret = -1;
	int32_t file_size;
	fs_file_t f = {0x00};

	ret = fs_open_file(&f, "attestation_key", LFS_O_RDONLY);
	if (ret < 0) {
		return ret;
	}

	file_size = fs_file_size(&f);
	if (file_size < 0) {
		ret = (int)file_size;
		fs_close_file(&f);
		return ret;
	}

	if (file_size > key_buf_size) {
		fs_close_file(&f);
		return -1;
	}

	ret = fs_read(&f, key_buf, file_size);
	fs_close_file(&f);
	if (ret < 0) {
		return ret;
	}

	return 0;
}

int device_attestation_write_key(uint8_t *key, size_t key_size)
{
	int ret = -1;
	fs_file_t f = {0x00};
	printf1(TAG_GREEN, "Writing attestation key with size %d\n", key_size);

	ret = fs_open_file(&f, "attestation_key", LFS_O_RDWR | LFS_O_CREAT);
	if (ret < 0) {
		return ret;
	}

	ret = fs_write(&f, key, key_size);
	if (ret < 0) {
		fs_close_file(&f);
		return ret;
	}

	ret = fs_truncate_file(&f, key_size);
	fs_close_file(&f);

	return ret;
}

int device_attestation_get_size_cert(uint16_t *size)
{
	int ret = -1;
	fs_file_t f = {0x00};

	ret = fs_open_file(&f, "attestation_cert", LFS_O_RDONLY);
	if (ret < 0) {
		return ret;
	}

	ret = fs_file_size(&f);
	fs_close_file(&f);
	if (ret < 0) {
		return ret;
	}

	*size = (uint16_t)ret;

	return 0;
}

int device_attestation_read_cert(uint8_t *cert_buf, size_t cert_buf_size)
{
	int ret = -1;
	int32_t file_size;
	fs_file_t f = {0x00};

	ret = fs_open_file(&f, "attestation_cert", LFS_O_RDONLY);
	if (ret < 0) {
		return ret;
	}

	file_size = fs_file_size(&f);
	if (file_size < 0) {
		ret = (int)file_size;
		fs_close_file(&f);
		return ret;
	}

	if (file_size > cert_buf_size) {
		fs_close_file(&f);
		return -1;
	}

	ret = fs_read(&f, cert_buf, file_size);
	fs_close_file(&f);
	if (ret < 0) {
		return ret;
	}

	return 0;
}

int device_attestation_write_cert(uint8_t *cert, size_t cert_size)
{
	int ret = -1;
	fs_file_t f = {0x00};
	printf1(TAG_GREEN, "Writing attestation cert with size %d\n",
		cert_size);

	ret = fs_open_file(&f, "attestation_cert", LFS_O_RDWR | LFS_O_CREAT);
	if (ret < 0) {
		return ret;
	}

	ret = fs_write(&f, cert, cert_size);
	if (ret < 0) {
		fs_close_file(&f);
		return ret;
	}

	ret = fs_truncate_file(&f, cert_size);
	fs_close_file(&f);

	return ret;
}
