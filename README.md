# Tillitis TKey FIDO2

WIP support for FIDO2 using the [Tillitis](https://tillitis.se/) TKey
USB security token.

Changes might be made to the fido2 device app, causing the identity to
change.

The FIDO2 device app is a fork of Solokeys [Solo1
firmware](https://github.com/solokeys/solo1/)

## Building

The build scripts assume that the [TKey device
libraries](https://github.com/tillitis/tkey-libs/) are located in
`../tkey-libs`. The location of tkey-libs can be configured using the
LIBDIR variable.

To build, run `make tkey_app`

See [Tillitis Developer Handbook](https://dev.tillitis.se/) for tool
support.

## Logging

Logging can be enabled by uncommenting `-DENABLE_PRINTF` and one of
`-DQEMU_DEBUG` and `-DTKEY_DEBUG` in `targets/tkey_app.mk`. See the
tkey-libs README for more information on the `*_DEBUG` defines. The
function `set_loggin_mask()` can then be used to enable logging of
specific parts of the system (see `targets/tkey/src/main.c`).

## Tkey requirements

The TKey need to present itself as a USB HID device, as well as the
usual CDC device. An experimental
[branch](https://github.com/tillitis/tillitis-key1/tree/ch552_hid_cdc/),
is available, containing bitstream for the FPGA and a firmware for the
USB interface.
