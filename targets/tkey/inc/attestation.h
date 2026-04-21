// SPDX-FileCopyrightText: 2026 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: Apache-2.0 OR MIT

#ifndef ATTESTATION_H
#define ATTESTATION_H

#include <stddef.h>
#include <stdint.h>

#define ATTESTATION_MAX_CERT_SIZE 1024
#define ATTESTATION_SIGN_KEY_SIZE 32
#define ATTESTATION_NONCE_SIZE 16
#define ATTESTATION_MAC_SIZE 16

typedef struct {
	uint8_t key_enc[ATTESTATION_SIGN_KEY_SIZE];
	uint8_t nonce[ATTESTATION_NONCE_SIZE];
	uint8_t mac[ATTESTATION_MAC_SIZE]; // mac = hmac(key_enc || nonce)
} __attribute__((packed)) att_key_t;

/** Read attestation key struct into key_buf.
 * The data is validated for authenticity.
 *
 * @param key_buf encrypted attestation private key and its metadata.
 * @return Returns zero on success, negative on error.
 */
int attestation_read_key(att_key_t *key_buf);

/** Write attestation key into the attestation_key file.
 * Encrypts and seals with a mac.
 *
 * @param key attestation private key.
 * @param key_size attestation private key size in bytes.
 * @return Returns zero on success, negative on error.
 */
int attestation_write_key(uint8_t *key, size_t key_size);

/** Read the device's attestation certificate into buffer cert_buf.
 * @param cert_buf certificate buffer to write the certificate to.
 * @param cert_buf_size size of certificate destination buffer.
 * @param cert_size size of certificate written to cert_buf.
 * @return Returns zero on success, negative on error.
 *
 * The size of the certificate can be retrieved using
 * `device_attestation_get_size_cert()`.
 */
int attestation_read_cert(uint8_t *cert_buf, size_t cert_buf_size,
			  size_t *cert_size);

/** Write attestation certificate into the attestation_cert file.
 * @param cert attestation certificate.
 * @param cert_size attestation certificate size in bytes.
 * @return Returns zero on success, negative on error.
 */
int attestation_write_cert(uint8_t *cert, size_t cert_size);

/** Read the device's 16 byte AAGUID into buffer dst.
 * @param dst buffer to write 16 byte AAGUID into.
 * */
void attestation_read_aaguid(uint8_t *dst);

#endif
