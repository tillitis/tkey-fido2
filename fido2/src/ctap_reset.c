#include <stdlib.h>

#include "crypto.h"
#include "ctap.h"
#include "ctap_client_pin.h"
#include "ctap_reset.h"
#include "device.h"
#include "log.h"

extern struct _getAssertionState getAssertionState;

void ctap_reset()
{
	ctap_state_init();

	authenticator_write_state(&STATE);

	ctap_reset_state();

	ctap_client_pin_reset_pin_token();
	ctap_client_pin_reset_key_agreement();

	crypto_derive_device_keys(STATE.key_salt, KEY_SALT_BYTES);
}

void ctap_reset_state()
{
	memset(&getAssertionState, 0, sizeof(getAssertionState));
}
