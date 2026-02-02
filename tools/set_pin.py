#!/usr/bin/env python3

import argparse
import sys
from fido2.hid import CtapHidDevice
from fido2.ctap2 import Ctap2, ClientPin

def find_authenticator():
    dev = next(CtapHidDevice.list_devices(), None)
    if dev is None:
        raise RuntimeError("No FIDO2 authenticator found")
    return dev

def set_pin(pin: str, old_pin:str):
    dev = find_authenticator()

    ctap2 = Ctap2(dev)

    info = ctap2.get_info()
    if info.options.get("clientPin"):
        if old_pin == None:
            print("Need old PIN to set a new. Use --old-pin..")
            return

        print("Changing PIN on authenticator...")
        ClientPin(ctap2).change_pin(old_pin, pin)
        print("PIN successfully changed")

        return
    else:

        print("Setting new PIN on authenticator...")
        ClientPin(ctap2).set_pin(pin)
        print("PIN successfully set")

def reset():
    dev = find_authenticator()
    ctap2 = Ctap2(dev)
    print("Resetting authenticator...")
    ctap2.reset()
    print("Successfully reset authenticator")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Set or change PIN on a FIDO2 authenticator")
    parser.add_argument(
        "--pin",
        required=False,
        type=str,
        default=None,
        help="New PIN to set on the authenticator",
    )
    parser.add_argument(
        "--old-pin",
        type=str,
        default=None,
        required=False,
        help="Old PIN. Required to change the pin.",
    )

    parser.add_argument(
        "--reset",
        action="store_true",
        required=False,
        help="Reset authenticator.",
    )

    args = parser.parse_args()


    if (args.pin != None) and (args.reset == True):
        print(f"Cannot reset and set pin. Choose one.")
        sys.exit(1)


    if args.reset:
        reset()
        sys.exit(0)

    if args.pin is None:
        print(f"PIN cannot be empty. Use --pin")
        sys.exit(1)

    set_pin(args.pin, args.old_pin)
    sys.exit(0)
