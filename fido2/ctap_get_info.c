// SPDX-FileCopyrightText: 2019 SoloKeys Developers
// SPDX-FileCopyrightText: 2026 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: Apache-2.0 OR MIT

#include <stdint.h>

#include "cose_key.h"
#include <cbor.h>
#include <cbor_util.h>
#include <ctap.h>
#include <ctap_errors.h>
#include <ctap_get_info.h>
#include <ctap_parse.h>
#include <device.h>

uint8_t ctap_get_info(CborEncoder *encoder)
{
	int ret;
	CborEncoder map;

	ret = cbor_encoder_create_map(encoder, &map, 9);
	check_ret(ret);
	{

		static const char *versions[] = {"U2F_V2", "FIDO_2_0",
						 "FIDO_2_1"};

		static const char *exts[] = {"credProtect", "hmac-secret"};

		ret = encode_str_array(&map, RESP_versions, versions, 3);
		check_ret(ret);
		ret = encode_str_array(&map, RESP_extensions, exts, 2);
		check_ret(ret);

		ret = cbor_encode_uint(&map, RESP_aaguid);
		check_ret(ret);
		{
			uint8_t aaguid[16];
			device_read_aaguid(aaguid);
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

				ret = encode_stringz_bool(&options, "rk", 1);
				check_ret(ret);
				ret = encode_stringz_bool(&options, "up", 1);
				check_ret(ret);
				ret = encode_stringz_bool(&options, "plat", 0);
				check_ret(ret);
				ret = encode_stringz_bool(&options, "credMgmt",
							  1);
				check_ret(ret);
				ret = encode_stringz_bool(&options, "clientPin",
							  ctap_is_pin_set());
				check_ret(ret);
			}
			ret = cbor_encoder_close_container(&map, &options);
			check_ret(ret);
		}

		ret = encode_uint_kv(&map, RESP_maxMsgSize,
				     CTAP_MAX_MESSAGE_SIZE);
		check_ret(ret);

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

		ret = encode_uint_kv(&map, RESP_maxCredentialCountInList,
				     ALLOW_LIST_MAX_SIZE);
		check_ret(ret);

		ret = encode_uint_kv(&map, RESP_maxCredentialIdLength,
				     MAX_CREDENTIAL_ID_SIZE);
		check_ret(ret);

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

				ret = encode_stringz_int(&alg_map, "alg",
							 COSE_ALG_EDDSA);
				check_ret(ret);
				ret = encode_stringz_stringz(&alg_map, "type",
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

				ret = encode_stringz_int(&alg_map, "alg",
							 COSE_ALG_ES256);
				check_ret(ret);
				ret = encode_stringz_stringz(&alg_map, "type",
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
