// SPDX-FileCopyrightText: 2019 SoloKeys Developers
// SPDX-FileCopyrightText: 2026 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: Apache-2.0 OR MIT

#include <stdint.h>

#include "cose_key.h"
#include <cbor.h>
#include <ctap.h>
#include <ctap_errors.h>
#include <ctap_parse.h>
#include <device.h>

#include "ctap_get_info.h"

uint8_t ctap_get_info(CborEncoder *encoder)
{
	int ret;
	CborEncoder map;
	uint8_t aaguid[16];
	device_read_aaguid(aaguid);

	ret = cbor_encoder_create_map(encoder, &map, 9);
	check_ret(ret);
	{

		ret = cbor_encode_uint(&map, RESP_versions); //  versions key
		check_ret(ret);
		{
			CborEncoder array;
			ret = cbor_encoder_create_array(&map, &array, 3);
			check_ret(ret);
			{
				ret =
				    cbor_encode_text_stringz(&array, "U2F_V2");
				check_ret(ret);
				ret = cbor_encode_text_stringz(&array,
							       "FIDO_2_0");
				check_ret(ret);
				ret = cbor_encode_text_stringz(&array,
							       "FIDO_2_1");
				check_ret(ret);
			}
			ret = cbor_encoder_close_container(&map, &array);
			check_ret(ret);
		}

		ret = cbor_encode_uint(&map, RESP_extensions);
		check_ret(ret);
		{
			CborEncoder array;
			ret = cbor_encoder_create_array(&map, &array, 2);
			check_ret(ret);
			{
				ret = cbor_encode_text_stringz(&array,
							       "credProtect");
				check_ret(ret);

				ret = cbor_encode_text_stringz(&array,
							       "hmac-secret");
				check_ret(ret);
			}
			ret = cbor_encoder_close_container(&map, &array);
			check_ret(ret);
		}

		ret = cbor_encode_uint(&map, RESP_aaguid);
		check_ret(ret);
		{
			ret = cbor_encode_byte_string(&map, aaguid, 16);
			check_ret(ret);
		}

		ret = cbor_encode_uint(&map, RESP_options);
		check_ret(ret);
		{
			CborEncoder options;
			ret = cbor_encoder_create_map(&map, &options, 5);
			check_ret(ret);
			{
				ret =
				    cbor_encode_text_string(&options, "rk", 2);
				check_ret(ret);
				{
					ret = cbor_encode_boolean(
					    &options, 1); // Capable of storing
							  // keys locally
					check_ret(ret);
				}

				ret =
				    cbor_encode_text_string(&options, "up", 2);
				check_ret(ret);
				{
					ret = cbor_encode_boolean(
					    &options, 1); // Capable of testing
							  // user presence
					check_ret(ret);
				}

				// NOT [yet] capable of verifying user
				// Do not add option if UV isn't supported.
				//
				// ret = cbor_encode_text_string(&options, "uv",
				// 2); check_ret(ret);
				// {
				//     ret = cbor_encode_boolean(&options, 0);
				//     check_ret(ret);
				// }

				ret = cbor_encode_text_string(&options, "plat",
							      4);
				check_ret(ret);
				{
					ret = cbor_encode_boolean(
					    &options,
					    0); // Not attached to platform
					check_ret(ret);
				}

				ret = cbor_encode_text_string(&options,
							      "credMgmt", 8);
				check_ret(ret);
				{
					ret = cbor_encode_boolean(&options, 1);
					check_ret(ret);
				}

				ret = cbor_encode_text_string(&options,
							      "clientPin", 9);
				check_ret(ret);
				{
					ret = cbor_encode_boolean(
					    &options, ctap_is_pin_set());
					check_ret(ret);
				}
			}
			ret = cbor_encoder_close_container(&map, &options);
			check_ret(ret);
		}

		ret = cbor_encode_uint(&map, RESP_maxMsgSize);
		check_ret(ret);
		{
			ret = cbor_encode_int(&map, CTAP_MAX_MESSAGE_SIZE);
			check_ret(ret);
		}

		ret = cbor_encode_uint(&map, RESP_pinUvAuthProtocols);
		check_ret(ret);
		{
			CborEncoder pins;
			ret = cbor_encoder_create_array(&map, &pins, 1);
			check_ret(ret);
			{
				ret = cbor_encode_int(&pins, 1);
				check_ret(ret);
			}
			ret = cbor_encoder_close_container(&map, &pins);
			check_ret(ret);
		}

		ret = cbor_encode_uint(&map, RESP_maxCredentialCountInList);
		check_ret(ret);
		{
			ret = cbor_encode_uint(&map, ALLOW_LIST_MAX_SIZE);
			check_ret(ret);
		}

		ret = cbor_encode_uint(&map, RESP_maxCredentialIdLength);
		check_ret(ret);
		{
			ret = cbor_encode_uint(&map, MAX_CREDENTIAL_ID_SIZE);
			check_ret(ret);
		}

		ret = cbor_encode_uint(&map, RESP_algorithms);
		check_ret(ret);

		{
			CborEncoder algs;
			ret = cbor_encoder_create_array(&map, &algs, 2);
			check_ret(ret);

			// Algorithm: EdDSA (-8)
			{
				CborEncoder alg_map;
				ret =
				    cbor_encoder_create_map(&algs, &alg_map, 2);
				check_ret(ret);

				ret = cbor_encode_text_stringz(&alg_map, "alg");
				check_ret(ret);
				ret = cbor_encode_int(&alg_map,
						      COSE_ALG_EDDSA);
				check_ret(ret);

				ret =
				    cbor_encode_text_stringz(&alg_map, "type");
				check_ret(ret);
				ret = cbor_encode_text_stringz(&alg_map,
							       "public-key");
				check_ret(ret);

				ret = cbor_encoder_close_container(&algs,
								   &alg_map);
				check_ret(ret);
			}

			// Algorithm: ES256 (-7)
			{
				CborEncoder alg_map;
				ret =
				    cbor_encoder_create_map(&algs, &alg_map, 2);
				check_ret(ret);

				ret = cbor_encode_text_stringz(&alg_map, "alg");
				check_ret(ret);
				ret = cbor_encode_int(&alg_map,
						      COSE_ALG_ES256);
				check_ret(ret);

				ret =
				    cbor_encode_text_stringz(&alg_map, "type");
				check_ret(ret);
				ret = cbor_encode_text_stringz(&alg_map,
							       "public-key");
				check_ret(ret);

				ret = cbor_encoder_close_container(&algs,
								   &alg_map);
				check_ret(ret);
			}

			ret = cbor_encoder_close_container(&map, &algs);
			check_ret(ret);
		}
	}
	ret = cbor_encoder_close_container(encoder, &map);
	check_ret(ret);

	return CTAP1_ERR_SUCCESS;
}
