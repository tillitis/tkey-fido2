# SPDX-FileCopyrightText: 2026 Tillitis AB <tillitis.se>
# SPDX-License-Identifier: BSD-2-Clause


import secrets

import pytest
from fido2.client import (
    ClientError,
    CtapError,
    DefaultClientDataCollector,
    Fido2Client,
    UserInteraction,
)
from fido2.hid import CtapHidDevice
from fido2.hid.base import FileCtapHidConnection, HidDescriptor
from fido2.webauthn import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialParameters,
    PublicKeyCredentialRequestOptions,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
)

from .tt.drivers.tkey import TKey


def find_authenticator(tty: str):
    descriptor = HidDescriptor(tty, 0x0000, 0x0000, 64, 64, "Tkey", 0)
    connection = FileCtapHidConnection(descriptor)
    dev = CtapHidDevice(descriptor, connection)
    if dev is None:
        raise RuntimeError("No FIDO2 authenticator found")
    return dev


class NonInteractive(UserInteraction):
    def __init__(self, pin):
        self.pin = pin

    def request_pin(self, permissions, retries):
        if self.pin is None:
            raise RuntimeError("Authenticator requested PIN, but none provided")
        return self.pin

    def request_uv(self, permissions):
        return True

    def on_keepalive(self, status):
        pass

    def prompt_up(self):
        if None:
            print("Authenticator requested user presence.")
        return True


def test_make_a_credential_and_assert_it(tkey: TKey) -> None:
    path = tkey.fido_port()
    dev = find_authenticator(path)

    rp_id = "example.com"
    user_id = bytes("user", encoding="utf-8")
    alg = -8
    rk = True
    pin = None

    origin = f"https://{rp_id}"
    collector = DefaultClientDataCollector(origin)

    interaction = NonInteractive(pin)

    client = Fido2Client(dev, collector, user_interaction=interaction)

    rp = PublicKeyCredentialRpEntity(
        id=rp_id,
        name="Benchmark RP",
    )

    user = PublicKeyCredentialUserEntity(
        id=user_id,
        name="user",
        display_name="User",
    )

    create_options = PublicKeyCredentialCreationOptions(
        rp=rp,
        user=user,
        challenge=secrets.token_bytes(32),
        pub_key_cred_params=[PublicKeyCredentialParameters(type="public-key", alg=alg)],
        timeout=60000,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key="required" if rk else False,
            user_verification="required" if pin else "discouraged",
        ),
    )

    registration_response = client.make_credential(create_options)
    print(registration_response)

    client = Fido2Client(dev, collector, user_interaction=interaction)

    # --- Authentication ---
    request_options = PublicKeyCredentialRequestOptions(
        challenge=secrets.token_bytes(32),
        timeout=60000,
        rp_id=rp.id,
        user_verification="required" if pin else "discouraged",
    )

    assertions = client.get_assertion(request_options)
    print(assertions)


def test_try_assert_a_non_existsing_credential(tkey: TKey) -> None:
    path = tkey.fido_port()
    dev = find_authenticator(path)

    pin = None
    rp_id = "example.com"

    origin = f"https://{rp_id}"
    collector = DefaultClientDataCollector(origin)

    interaction = NonInteractive(pin)

    client = Fido2Client(dev, collector, user_interaction=interaction)

    rp = PublicKeyCredentialRpEntity(
        id=rp_id,
        name="Benchmark RP",
    )

    client = Fido2Client(dev, collector, user_interaction=interaction)

    # --- Authentication ---
    request_options = PublicKeyCredentialRequestOptions(
        challenge=secrets.token_bytes(32),
        timeout=60000,
        rp_id=rp.id,
        user_verification="discouraged",
    )

    with pytest.raises(ClientError) as exc:
        client.get_assertion(request_options)


    assert exc.value.code == ClientError.ERR.DEVICE_INELIGIBLE
    assert exc.value.cause.code == CtapError.ERR.NO_CREDENTIALS

