// SPDX-FileCopyrightText: 2019 SoloKeys Developers
// SPDX-FileCopyrightText: 2026 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: Apache-2.0 OR MIT

#include "ctap_reset.h"
#include "crypto.h"
#include "ctap_client_pin.h"
#include "device.h"

extern struct _getAssertionState getAssertionState;

void ctap_reset(void)
{
	ctap_state_init();

	authenticator_write_state(&STATE);

	ctap_reset_state();
	ctap_client_pin_initialize();

	crypto_derive_session_keys(STATE.key_salt, STATE_KEY_SALT_BYTES);
}

void ctap_reset_state(void)
{
	memset(&getAssertionState, 0, sizeof(getAssertionState));
}
