import os
import time
import secrets
import signal
import sys
import argparse

from collections import defaultdict
from statistics import mean

from fido2.hid import CtapHidDevice
from fido2.client import Fido2Client, DefaultClientDataCollector, UserInteraction, AssertionSelection
from fido2.webauthn import (
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
    PublicKeyCredentialParameters,
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialRequestOptions,
    PublicKeyCredentialDescriptor,
    AuthenticatorSelectionCriteria,
)

_stop_requested = False
verbose = False
csv = False
static_rp = False
bucket = True

def _handle_sigint(signum, frame):
    global _stop_requested
    print("\nStopping.. ")
    _stop_requested = True

signal.signal(signal.SIGINT, _handle_sigint)

results = []
BUCKETS = [1, 2, 5, 10, 20, 50, 100, 200, 500, 1000]
bucketed = defaultdict(list)


def bucket_for(n):
    for b in BUCKETS:
        if n <= b:
            return b
    return BUCKETS[-1]

def print_buckets():
    for r in results:
        bucket = bucket_for(r["stored_creds"])
        bucketed[bucket].append(r)


    summary = {}

    for bucket, entries in bucketed.items():
        reg = [e["registration_time"] for e in entries]
        auth = [e["authentication_time"] for e in entries]

        summary[bucket] = {
            "count": len(entries),
            "registration": {
                "mean": mean(reg),
                "min": min(reg),
                "max": max(reg),
            },
            "authentication": {
                "mean": mean(auth),
                "min": min(auth),
                "max": max(auth),
            },
        }


    for bucket in sorted(summary):
        s = summary[bucket]
        print(f"\n≤ {bucket} stored credentials ({s['count']} samples)")
        print(
            f"  reg  mean {s['registration']['mean']:.3f}s "
            f"min {s['registration']['min']:.3f}s "
            f"max {s['registration']['max']:.3f}s"
        )
        print(
            f"  auth mean {s['authentication']['mean']:.3f}s "
            f"min {s['authentication']['min']:.3f}s "
            f"max {s['authentication']['max']:.3f}s"
        )

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
        if verbose:
            print("Authenticator requested user presence.")
        return True

def find_authenticator():
    dev = next(CtapHidDevice.list_devices(), None)
    if dev is None:
        raise RuntimeError("No FIDO2 authenticator found")
    return dev

def benchmark_fido2(num_creds=1, pin=None, alg=-8):
    # --- Locate authenticator ---
    dev = find_authenticator()


    total_start = time.perf_counter()
    reg_times = []
    auth_times = []

    rp_id = "benchmark.com"

    for i in range(num_creds):
        if _stop_requested:
            break

        stored_creds = i + 1

        if not static_rp:
            rp_id = f"{secrets.token_hex(4)}.benchmark.com"

        origin = f"https://{rp_id}"
        collector = DefaultClientDataCollector(origin)

        interaction = NonInteractive(pin)

        client = Fido2Client(dev, collector, user_interaction=interaction)

        rp = PublicKeyCredentialRpEntity(
            id=rp_id,
            name="Benchmark RP",
        )

        user = PublicKeyCredentialUserEntity(
            id=os.urandom(32),
            name=f"user{i}",
            display_name=f"User {i}",
        )

        create_options = PublicKeyCredentialCreationOptions(
            rp=rp,
            user=user,
            challenge=secrets.token_bytes(32),
            pub_key_cred_params=[PublicKeyCredentialParameters(type="public-key", alg=alg)],
            timeout=60000,
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key="required",
                user_verification="required" if pin else "discouraged"
            )
        )

        # --- Registration ---
        t0 = time.perf_counter()
        registration_response = client.make_credential(create_options)
        t1 = time.perf_counter()
        reg_time = t1 - t0

        cred_id = registration_response.response.attestation_object.auth_data.credential_data.credential_id

        # --- Authentication ---
        request_options = PublicKeyCredentialRequestOptions(
            challenge=secrets.token_bytes(32),
            timeout=60000,
            rp_id=rp.id,
            allow_credentials=[PublicKeyCredentialDescriptor(type="public-key", id=cred_id)],
            user_verification="required" if pin else "discouraged",
        )

        t2 = time.perf_counter()
        assertions = client.get_assertion(request_options)
        t3 = time.perf_counter()
        auth_time = t3 - t2

        results.append({
            "stored_creds": stored_creds,
            "registration_time": reg_time,
            "authentication_time": auth_time,
        })

        print(
            f"Creds stored: {stored_creds:3d} | "
            f"reg: {reg_time:.3f}s | auth: {auth_time:.3f}s"
        )

    total_end = time.perf_counter()
    print(f"\nTotal time for {stored_creds} credentials: {total_end - total_start:.3f}s")


    reg_times = [r["registration_time"] for r in results]
    auth_times = [r["authentication_time"] for r in results]

    stats = {
        "registration": {
            "mean": mean(reg_times),
            "min": min(reg_times),
            "max": max(reg_times),
        },
        "authentication": {
            "mean": mean(auth_times),
            "min": min(auth_times),
            "max": max(auth_times),
        },
    }

    print("\nRegistration time:")
    print(f"  mean: {stats['registration']['mean']:.3f}s  min : {stats['registration']['min']:.3f}s  max : {stats['registration']['max']:.3f}s")

    print("\nAuthentication time:")
    print(f"  mean: {stats['authentication']['mean']:.3f}s  min : {stats['authentication']['min']:.3f}s  max : {stats['authentication']['max']:.3f}s")

    if bucket:
        print_buckets()

    if csv:
        print("\n--- CSV ---")
        for r in results:
            print(
                f"{r['stored_creds']:3d},"
                f"{r['registration_time']:.6f},"
                f"{r['authentication_time']:.6f}"
            )


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="FIDO2 credential benchmark")
    parser.add_argument("--static-rp", action="store_true", help="Use a static RP ID for all credentials. Default is a random (new RP per credential)")
    parser.add_argument("--num-creds", type=int, default=1, help="Number of credentials to create. Default 1.")
    parser.add_argument("--pin", type=str, default=None, help="PIN to use. Default None")
    parser.add_argument("--alg", type=int, default=-8, help="Algorithm to use, use -8 for EdDSA and -7 for ES256. Default EdDSA.")
    parser.add_argument("--csv", action="store_true", help="Print an CSV output at the end of the run.")
    parser.add_argument("--no-bucket", action="store_false", help="Don't print an bucketed list.")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()
    verbose = args.verbose
    csv = args.csv
    static_rp = args.static_rp
    bucket = args.no_bucket

    if args.alg in (-7,-8):
        benchmark_fido2(
            num_creds=args.num_creds,
            pin=args.pin,
            alg=args.alg)

        sys.exit(0)

    print(f"Algorithm not supported: {args.alg}")
    sys.exit(1)
