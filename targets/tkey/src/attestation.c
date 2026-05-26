// SPDX-FileCopyrightText: 2019 SoloKeys Developers
// SPDX-FileCopyrightText: 2024 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: Apache-2.0 OR MIT

#include "attestation.h"
#include "crypto.h"
#include "fs.h"
#include "log.h"
#include "rng.h"

#include <stdint.h>
#include <string.h>

int attestation_read_key(att_key_t *key_buf)
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

	if (file_size != sizeof(att_key_t)) {
		fs_close_file(&f);
		return -1;
	}

	ret = fs_read(&f, key_buf, (size_t)file_size);
	fs_close_file(&f);
	if (ret < 0) {
		return ret;
	}

	// Verify mac
	if (!crypto_verify_device_mac(
		key_buf, ATTESTATION_SIGN_KEY_SIZE + ATTESTATION_NONCE_SIZE,
		key_buf->mac, ATTESTATION_MAC_SIZE)) {
		printf1(TAG_GREEN, "att_read_key: mac not valid\n");

		memset(key_buf, 0x00, sizeof(att_key_t));

		return -1;
	}

	return 0;
}

int attestation_write_key(uint8_t *key, size_t key_size)
{
	int ret = -1;
	fs_file_t f = {0x00};

	if (key_size != ATTESTATION_SIGN_KEY_SIZE) {
		printf1(TAG_ERR, "Key not right length %d\n", key_size);
		return -1;
	}

	printf1(TAG_GREEN, "Writing attestation key with size %d\n", key_size);

	ret = fs_open_file(&f, "attestation_key", LFS_O_RDWR | LFS_O_CREAT);
	if (ret < 0) {
		return ret;
	}

	int size = fs_file_size(&f);
	if (size < 0) {
		fs_close_file(&f);
		return size;
	}

	if (size > 0) {
		// Already present
		printf1(TAG_GREEN, "Attestation key already present, abort\n");
		fs_close_file(&f);
		return -1;
	}

	att_key_t att_key = {0};
	memmove(att_key.key_enc, key, key_size);
	// Generate nonce
	rng_get_bytes(att_key.nonce, ATTESTATION_NONCE_SIZE);
	// Encrypt
	const uint8_t *encryption_key = crypto_get_key_device_enc();
	crypto_aes256_ctr_xcrypt_buffer(encryption_key, att_key.nonce,
					att_key.key_enc,
					ATTESTATION_SIGN_KEY_SIZE);
	// Calculate mac
	crypto_compute_device_mac(
	    &att_key, ATTESTATION_SIGN_KEY_SIZE + ATTESTATION_NONCE_SIZE,
	    att_key.mac, ATTESTATION_MAC_SIZE);
	// Store
	ret = fs_write(&f, &att_key, sizeof(att_key_t));
	if (ret < 0) {
		fs_close_file(&f);
		return ret;
	}

	fs_close_file(&f);

	return ret;
}

int attestation_read_cert(uint8_t *cert_buf, size_t cert_buf_size,
			  size_t *cert_size)
{
	int ret = -1;
	int file_size = 0;
	fs_file_t f = {0x00};

	ret = fs_open_file(&f, "attestation_cert", LFS_O_RDONLY);

	if (ret < 0) {
		return ret;
	}

	file_size = fs_file_size(&f);
	if (file_size < 0) {
		fs_close_file(&f);
		return file_size;
	}

	if ((size_t)file_size > cert_buf_size) {
		fs_close_file(&f);
		return -1;
	}
	*cert_size = (size_t)file_size;

	ret = fs_read(&f, cert_buf, (size_t)file_size);

	fs_close_file(&f);
	if (ret < 0) {
		return ret;
	}

	return 0;
}

int attestation_write_cert(uint8_t *cert, size_t cert_size)
{
	int ret = -1;
	fs_file_t f = {0x00};

	if (cert_size > ATTESTATION_MAX_CERT_SIZE) {
		printf1(TAG_ERR, "Cert to large %d\n", cert_size);
		return -1;
	}

	printf1(TAG_GREEN, "Writing attestation cert with size %d\n",
		cert_size);

	ret = fs_open_file(&f, "attestation_cert", LFS_O_RDWR | LFS_O_CREAT);
	if (ret < 0) {
		return ret;
	}

	int size = fs_file_size(&f);
	if (size < 0) {
		fs_close_file(&f);
		return size;
	}

	if (size > 0) {
		// Already present
		printf1(TAG_GREEN, "Cert already present, abort\n");
		fs_close_file(&f);
		return -1;
	}

	ret = fs_write(&f, cert, cert_size);
	if (ret < 0) {
		fs_close_file(&f);
		return ret;
	}

	fs_close_file(&f);

	return ret;
}

void attestation_read_aaguid(uint8_t *dst)
{
	uint8_t *aaguid = (uint8_t *)"\xdb\xe4\x2d\x66\x22\xbe\x46\x24\x88\x11"
				     "\x97\x2a\x8e\x65\x36\x7e";
	memmove(dst, aaguid, 16);
}
