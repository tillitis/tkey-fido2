# Tillitis TKey FIDO2

WIP support for FIDO2 using the [Tillitis](https://tillitis.se/)
TKey USB security token.

Changes might be made to the fido2 device app, causing the identity
to change.

The FIDO2 device app is a fork of Solokeys [Solo1 firmware](https://github.com/solokeys/solo1/)

## Building

The build scripts assume that the [TKey device libraries](https://github.com/tillitis/tkey-libs/)
are located in `../tkey-libs`.

To build, run `make tkey_app`

See [Tillitis Developer Handbook](https://dev.tillitis.se/) for tool
support.

## Tkey requirements

The TKey need to present itself as a USB HID device, as well as the
usual CDC device. An experimental [branch](https://github.com/tillitis/tillitis-key1/tree/ch552_hid_cdc/),
is available, containing bitstream for the FPGA and a firmware for
the USB interface.

