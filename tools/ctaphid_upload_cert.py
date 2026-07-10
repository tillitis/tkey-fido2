# SPDX-FileCopyrightText: 2026 Tillitis AB <tillitis.se>
# SPDX-License-Identifier: BSD-2-Clause

import argparse
import hid
import os
import struct
import sys
import time

# Usa as:
# python3 ctaphid_upload_cert.py --cert-file tkey_cert.der --key-file tkey_private_key.bin

# ---------------------------
# Device IDs (adjust these!)
# ---------------------------
VID = 0x1209
PID = 0x8885

# ---------------------------
# CTAPHID constants
# ---------------------------
CTAPHID_INIT = 0x06
CTAPHID_WRITE_CERT = 0x51
CTAPHID_WRITE_KEY = 0x52
CTAPHID_GETVERSION = 0x61


CHANNEL_BROADCAST = 0xffffffff

# ---------------------------
# CTAPHID framing helpers
# ---------------------------
def ctaphid_frame(cmd, payload=b"", cid=CHANNEL_BROADCAST):
    packets = []

    total_len = len(payload)

    # --- First (INIT) packet ---
    init_payload = payload[:57]
    header = struct.pack(">IBH", cid, cmd | 0x80, total_len)
    packet = (header + init_payload).ljust(64, b"\x00")
    packets.append(packet)

    # --- Continuation packets ---
    seq = 0
    offset = 57

    while offset < total_len:
        chunk = payload[offset:offset + 59]
        cont_header = struct.pack(">IB", cid, seq)
        packet = (cont_header + chunk).ljust(64, b"\x00")
        packets.append(packet)

        offset += len(chunk)
        seq += 1

    return packets

def parse_response(data):
    cid = struct.unpack(">I", data[0:4])[0]
    cmd = data[4] & 0x7f
    length = struct.unpack(">H", data[5:7])[0]
    payload = data[7:7+length]
    return cid, cmd, payload, length

def ctaphid_init(dev):
    nonce = os.urandom(8)
    frames = ctaphid_frame(CTAPHID_INIT, nonce, 0xffffffff)
    for f in frames:
        dev.write(f)
    resp = bytes(dev.read(64, timeout=3000))

    cid, cmd, payload, len = parse_response(bytes(resp))
    print(f"INIT response: cid=0x{cid:08x}, cmd={hex(cmd)}, payload={payload.hex()}, len={len}")

    if payload[:8] != nonce:
        raise RuntimeError("Nonce mismatch")

    new_cid = struct.unpack(">I", payload[8:12])[0]
    return new_cid
# ---------------------------J
# Main
# ---------------------------
def load_file(path):
    if path is None:
        return None

    with open(path, "rb") as f:
        return f.read()

def main():

    ret = 0
    parser = argparse.ArgumentParser(
        description="Upload an attestation certificate and/or private key to a TKey FIDO2 device over CTAPHID."
    )
    parser.add_argument("--cert-file", type=str, default=None, help="Path to the attestation certificate (DER format)")
    parser.add_argument("--key-file", type=str, default=None, help="Path to the private key (raw binary)")

    args = parser.parse_args()

    cert_payload = load_file(args.cert_file)
    key_payload = load_file(args.key_file)

    if not (args.cert_file or args.key_file):
        print(f"need at least key or cert\n")
        sys.exit(1)

    vid = 0x1209
    pid = 0x8885
    target_interface = 2

    print(f"Trying to connect to {hex(vid)}:{hex(pid)}:{target_interface}")

    # Find the interface
    found = False
    while not found:
        for dev in hid.enumerate():
            if (
                dev['vendor_id'] == vid and
                dev['product_id'] == pid and
                dev.get('interface_number') == target_interface
            ):
                binary_hid_path = dev['path']
                found = True
                break

        # raise RuntimeError("Desired interface not found")
        time.sleep(0.02)

    print(f"\nConnected to {hex(vid)}:{hex(pid)}:{target_interface} ---------------------------------")

    hid_path = binary_hid_path.decode('utf-8')

    dev = hid.Device(path=binary_hid_path)

    print("Device opened")

    # --- INIT ---
    cid = ctaphid_init(dev)
    print(f"cid=0x{cid:08x}\n")

    if cert_payload:
        print(f"Sending cert..")
        frames = ctaphid_frame(CTAPHID_WRITE_CERT, cert_payload, cid)
        for f in frames:
            dev.write(f)
            time.sleep(0.01)

        resp = bytes(dev.read(64, timeout=3000))
        cid, cmd, payload, len= parse_response(bytes(resp))
        # print(f"cert response: cid=0x{cid:08x}, cmd={hex(cmd)}, payload={payload.hex()}, len={len}")
        if payload[0] != 0:
            print(f"Writing cert failed: {payload.hex()}")
            ret = 1
        else:
            print(f"done\n")


    if key_payload:
        print(f"Sending key..")
        frames = ctaphid_frame(CTAPHID_WRITE_KEY, key_payload, cid)
        for f in frames:
            dev.write(f)
            time.sleep(0.01)

        resp = bytes(dev.read(64, timeout=3000))
        cid, cmd, payload, len = parse_response(bytes(resp))
        # print(f"cert response: cid=0x{cid:08x}, cmd={hex(cmd)}, payload={payload.hex()}, len={len}")
        if payload[0] != 0:
            print(f"Writing key failed: {payload.hex()}")
            ret = 1
        else:
            print(f"done\n")

    dev.close()
    sys.exit(ret)

if __name__ == "__main__":
    main()
