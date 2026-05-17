// SPDX-FileCopyrightText: 2019 SoloKeys Developers
// SPDX-FileCopyrightText: 2026 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: Apache-2.0 OR MIT

#include <stdint.h>

#include "ctap_client_pin.h"
#include "ctap_errors.h"
#include "ctap_get_info.h"
#include "ctap_parse.h"
#include "device.h"
#include <attestation.h>

CtapStatus ctap_get_info(CborEncoder *encoder)
{
	CborError cbor_ret;
	CborEncoder array;
	CborEncoder map;
	CborEncoder options;
	CborEncoder pins;
	uint8_t aaguid[16];
	attestation_read_aaguid(aaguid);

	cbor_ret = cbor_encoder_create_map(encoder, &map, 8);
	cbor_check_ret(cbor_ret);
	{

		cbor_ret = cbor_encode_uint(&map, GI_Resp_versions);
		cbor_check_ret(cbor_ret);
		{
			cbor_ret = cbor_encoder_create_array(&map, &array, 3);
			cbor_check_ret(cbor_ret);
			{
				cbor_ret =
				    cbor_encode_text_stringz(&array, "U2F_V2");
				cbor_check_ret(cbor_ret);
				cbor_ret = cbor_encode_text_stringz(&array,
								    "FIDO_2_0");
				cbor_check_ret(cbor_ret);
				cbor_ret = cbor_encode_text_stringz(&array,
								    "FIDO_2_1");
				cbor_check_ret(cbor_ret);
			}
			cbor_ret = cbor_encoder_close_container(&map, &array);
			cbor_check_ret(cbor_ret);
		}

		cbor_ret = cbor_encode_uint(&map, GI_Resp_extensions);
		cbor_check_ret(cbor_ret);
		{
			cbor_ret = cbor_encoder_create_array(&map, &array, 2);
			cbor_check_ret(cbor_ret);
			{
				cbor_ret = cbor_encode_text_stringz(
				    &array, "credProtect");
				cbor_check_ret(cbor_ret);

				cbor_ret = cbor_encode_text_stringz(
				    &array, "hmac-secret");
				cbor_check_ret(cbor_ret);
			}
			cbor_ret = cbor_encoder_close_container(&map, &array);
			cbor_check_ret(cbor_ret);
		}

		cbor_ret = cbor_encode_uint(&map, GI_Resp_aaguid);
		cbor_check_ret(cbor_ret);
		{
			cbor_ret = cbor_encode_byte_string(&map, aaguid, 16);
			cbor_check_ret(cbor_ret);
		}

		cbor_ret = cbor_encode_uint(&map, GI_Resp_options);
		cbor_check_ret(cbor_ret);
		{
			cbor_ret = cbor_encoder_create_map(&map, &options, 5);
			cbor_check_ret(cbor_ret);
			{
				cbor_ret =
				    cbor_encode_text_string(&options, "rk", 2);
				cbor_check_ret(cbor_ret);
				{
					cbor_ret = cbor_encode_boolean(
					    &options, 1); // Capable of storing
							  // keys locally
					cbor_check_ret(cbor_ret);
				}

				cbor_ret =
				    cbor_encode_text_string(&options, "up", 2);
				cbor_check_ret(cbor_ret);
				{
					cbor_ret = cbor_encode_boolean(
					    &options, 1); // Capable of testing
							  // user presence
					cbor_check_ret(cbor_ret);
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

				cbor_ret = cbor_encode_text_string(&options,
								   "plat", 4);
				cbor_check_ret(cbor_ret);
				{
					cbor_ret = cbor_encode_boolean(
					    &options,
					    0); // Not attached to platform
					cbor_check_ret(cbor_ret);
				}

				cbor_ret = cbor_encode_text_string(
				    &options, "credMgmt", 8);
				cbor_check_ret(cbor_ret);
				{
					cbor_ret =
					    cbor_encode_boolean(&options, 1);
					cbor_check_ret(cbor_ret);
				}

				cbor_ret = cbor_encode_text_string(
				    &options, "clientPin", 9);
				cbor_check_ret(cbor_ret);
				{
					cbor_ret = cbor_encode_boolean(
					    &options, ctap_client_pin_is_set());
					cbor_check_ret(cbor_ret);
				}
			}
			cbor_ret = cbor_encoder_close_container(&map, &options);
			cbor_check_ret(cbor_ret);
		}

		cbor_ret = cbor_encode_uint(&map, GI_Resp_maxMsgSize);
		cbor_check_ret(cbor_ret);
		{
			cbor_ret = cbor_encode_int(&map, CTAP_MAX_MESSAGE_SIZE);
			cbor_check_ret(cbor_ret);
		}

		cbor_ret = cbor_encode_uint(&map, GI_Resp_pinUvAuthProtocols);
		cbor_check_ret(cbor_ret);
		{
			cbor_ret = cbor_encoder_create_array(&map, &pins, 2);
			cbor_check_ret(cbor_ret);
			{
				cbor_ret = cbor_encode_int(&pins, 1);
				cbor_check_ret(cbor_ret);

				cbor_ret = cbor_encode_int(&pins, 2);
				cbor_check_ret(cbor_ret);
			}
			cbor_ret = cbor_encoder_close_container(&map, &pins);
			cbor_check_ret(cbor_ret);
		}

		cbor_ret =
		    cbor_encode_uint(&map, GI_Resp_maxCredentialCountInList);
		cbor_check_ret(cbor_ret);
		{
			cbor_ret = cbor_encode_uint(&map, ALLOW_LIST_MAX_SIZE);
			cbor_check_ret(cbor_ret);
		}

		cbor_ret =
		    cbor_encode_uint(&map, GI_Resp_maxCredentialIdLength);
		cbor_check_ret(cbor_ret);
		{
			cbor_ret = cbor_encode_uint(&map, 128);
			cbor_check_ret(cbor_ret);
		}
	}
	cbor_ret = cbor_encoder_close_container(encoder, &map);
	cbor_check_ret(cbor_ret);

	return (CtapStatus){CTAP2_OK};
}
