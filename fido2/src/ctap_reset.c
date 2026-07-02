// SPDX-FileCopyrightText: 2019 SoloKeys Developers
// SPDX-FileCopyrightText: 2026 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: Apache-2.0 OR MIT

#include "ctap_reset.h"
#include "crypto.h"
#include "ctap_client_pin.h"
#include "ctap_errors.h"
#include "ctap_parse.h"
#include "device.h"

extern struct _getAssertionState getAssertionState;

#define AUTHENTICATOR_RESET_TIME_MS (10 * 1000) // 10 seconds

CtapStatus ctap_reset(void)
{
#if !(defined(DEBUG_LEVEL) && (DEBUG_LEVEL > 0))
	if (millis() > AUTHENTICATOR_RESET_TIME_MS) {
		return (CtapStatus){CTAP2_ERR_NOT_ALLOWED};
	}
#endif

	CtapStatus ctap_ret = ctap2_user_presence_test();
	ctap_check_retr(ctap_ret);

	ctap_state_init();

	authenticator_write_state(&STATE);

	ctap_reset_state();
	ctap_client_pin_initialize();

	crypto_derive_session_keys(STATE.key_salt, STATE_KEY_SALT_BYTES);

	return (CtapStatus){CTAP2_OK};
}

void ctap_reset_state(void)
{
	memset(&getAssertionState, 0, sizeof(getAssertionState));
}
