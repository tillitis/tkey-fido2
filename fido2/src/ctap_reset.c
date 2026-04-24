#include <stdlib.h>

#include "crypto.h"
#include "ctap.h"
#include "ctap_client_pin.h"
#include "ctap_reset.h"
#include "device.h"
#include "log.h"

extern uint8_t KEY_AGREEMENT_PRIV[32];
extern uint8_t PIN_TOKEN[PIN_TOKEN_SIZE];
extern struct _getAssertionState getAssertionState;

void ctap_reset()
{
	ctap_state_init();

	authenticator_write_state(&STATE);

	if (ctap_generate_rng(PIN_TOKEN, PIN_TOKEN_SIZE) != 1) {
		printf2(TAG_ERR, "Error, rng failed\n");
		exit(1);
	}

	ctap_reset_state();
	ctap_reset_key_agreement();

	crypto_derive_device_keys(STATE.key_salt, KEY_SALT_BYTES);
}

void ctap_reset_key_agreement()
{
	ctap_generate_rng(KEY_AGREEMENT_PRIV, sizeof(KEY_AGREEMENT_PRIV));
}

void ctap_reset_state()
{
	memset(&getAssertionState, 0, sizeof(getAssertionState));
}
