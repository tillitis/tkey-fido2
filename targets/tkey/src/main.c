// Copyright 2019 SoloKeys Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>


#include "ctaphid.h"
#include "log.h"
#include "fifo.h"
#include APP_CONFIG

#include "tkey/debug.h"
#include "tkey/tk1_mem.h"
#include "tkey/led.h"
#include "tkey/proto.h"
#include "frame.h"

#include "rng.h"

// P-256
#include "p256-m.h"

// MbedTLS
#include "mbedtls/ecdsa.h"

#define TIME_CRYPTO_FUNCTIONS // Instead of being a FIDO2 app, time some crypto
                              // functions every time a message comes on the
                              // FIDO endpoint.

#define HID_PACKET_SIZE 64

// clang-format off
//static volatile uint32_t *cdi           = (volatile uint32_t *) TK1_MMIO_TK1_CDI_FIRST;
static volatile uint32_t *cpu_mon_ctrl  = (volatile uint32_t *) TK1_MMIO_TK1_CPU_MON_CTRL;
static volatile uint32_t *cpu_mon_first = (volatile uint32_t *) TK1_MMIO_TK1_CPU_MON_FIRST;
static volatile uint32_t *cpu_mon_last  = (volatile uint32_t *) TK1_MMIO_TK1_CPU_MON_LAST;
static volatile uint32_t *app_addr      = (volatile uint32_t *) TK1_MMIO_TK1_APP_ADDR;
static volatile uint32_t *app_size      = (volatile uint32_t *) TK1_MMIO_TK1_APP_SIZE;
// clang-format on

static void sign_stuff(void);

int main()
{
    uint8_t hidmsg[HID_PACKET_SIZE];
    uint8_t data[HID_PACKET_SIZE];

    // Use Execution Monitor on RAM after app
    *cpu_mon_first = *app_addr + *app_size;
    *cpu_mon_last = TK1_RAM_BASE + TK1_RAM_SIZE;
    *cpu_mon_ctrl = 1;

    led_set(LED_BLUE);

    set_logging_mask(
            // TAG_GEN |
            // TAG_MC |
            // TAG_GA |
            // TAG_WALLET |
            // TAG_STOR |
            // TAG_CP |
            // TAG_CTAP |
            // TAG_HID |
            // TAG_U2F |
            // TAG_PARSE |
            // TAG_TIME |
            // TAG_DUMP |
            // TAG_GREEN |
            // TAG_RED |
            // TAG_EXT |
            // TAG_CCID |
            TAG_PROF |
            // TAG_ERR |
            0
    );

#ifdef TIME_CRYPTO_FUNCTIONS
#include "init.h"
    init_millisecond_timer();
    init_usb();
    init_rng();
#else
    device_init();
#endif

    memset(hidmsg,0,sizeof(hidmsg));

    while(1)
    {
        enum ioend ep;
        uint8_t available;

        if (readselect(IO_FIDO, &ep, &available) != 0) {
            assert(1 == 2);
        }

#ifdef TIME_CRYPTO_FUNCTIONS
        if (read(IO_FIDO, data, sizeof(data), available) != HID_PACKET_SIZE) {
            assert(1 == 2);
        }

        sign_stuff();
        continue;
#else

        if (available != HID_PACKET_SIZE) {
            continue;
        }

        if (read(IO_FIDO, data, sizeof(data), available) != HID_PACKET_SIZE) {
            assert(1 == 2);
        }

        if (fifo_hidmsg_add(data) != 0) {
            return -1;
        }

        if (usbhid_recv(hidmsg) > 0) {
            ctaphid_handle_packet(hidmsg);
            memset(hidmsg, 0, sizeof(hidmsg));
        } else {
        }

        ctaphid_check_timeouts();
#endif
    }

    // Should never get here
    usbhid_close();
    printf1(TAG_GREEN, "done\n");
    assert(1 == 2);
    return 0;
}

static int random_mbedtls(void *p_rng, unsigned char *output, size_t output_len)
{
    return rng_get_bytes(output, output_len);
}

// Sign a randomly generated value (the value which normally would be a hash of
// the message). Then verify the signature.
//
// Adapted from crypto/mbedtls/tests/suites/test_suite_ecdsa.function testcase
// test_ecdsa_prim_random.
static void test_ecdsa_prim_random(int id)
{
    mbedtls_ecp_group grp;
    mbedtls_ecp_point Q;
    mbedtls_mpi d, r, s;
    unsigned char buf[32];

    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&Q);
    mbedtls_mpi_init(&d); mbedtls_mpi_init(&r); mbedtls_mpi_init(&s);
    memset(buf, 0, sizeof(buf));
    rng_get_bytes(buf, sizeof(buf));

    int ret = 0;

    /* prepare material for signature */
    PROFILE_BEGIN
    if ((ret = mbedtls_ecp_group_load(&grp, id)) != 0) {
        debug_puts("mbedtls_ecp_group_load failed. error: ");
        debug_putinthex(ret);
        debug_lf();

        goto exit;
    }
    PROFILE_END("mbedtls_ecp_group_load");

    PROFILE_BEGIN
    if ((ret = mbedtls_ecp_gen_keypair(&grp, &d, &Q, random_mbedtls,
                                       NULL)) != 0) {
        debug_puts("mbedtls_ecp_gen_keypair failed. error: ");
        debug_putinthex(ret);
        debug_lf();

        goto exit;
    }
    PROFILE_END("mbedtls_ecp_gen_keypair");

    PROFILE_BEGIN
    if ((ret = mbedtls_ecdsa_sign(&grp, &r, &s, &d, buf, sizeof(buf),
                                   random_mbedtls, NULL)) != 0) {
        debug_puts("mbedtls_ecdsa_sign failed. error: ");
        debug_putinthex(ret);
        debug_lf();

        goto exit;
    }
    PROFILE_END("mbedtls_ecdsa_sign");

    // If verifying. Increase memory in malloc_block.c:
    //
    // struct block {
    //     uint8_t data[192];
    //     ...
    //     uint8_t padding[31];
    // }
    // _Static_assert(sizeof(struct block) == 224 ...
    // struct block blocks[60] __attribute__((aligned(16))) = {0};
    // PROFILE_BEGIN
    // if ((ret = mbedtls_ecdsa_verify(&grp, buf, sizeof(buf), &Q, &r, &s)) != 0) {
    //     debug_puts("mbedtls_ecdsa_verify failed. error: ");
    //     debug_putinthex(ret);
    //     debug_lf();

    //     goto exit;
    // }
    // PROFILE_END("mbedtls_ecdsa_verify");

exit:
    mbedtls_ecp_group_free(&grp);
    mbedtls_ecp_point_free(&Q);
    mbedtls_mpi_free(&d); mbedtls_mpi_free(&r); mbedtls_mpi_free(&s);
}

static void sign_with_mbedtls(void)
{
    test_ecdsa_prim_random(MBEDTLS_ECP_DP_SECP256R1);
}

// p256_generate_random is needed by p256-m
int p256_generate_random(uint8_t * output, unsigned output_size) {
    return rng_get_bytes(output, output_size);
}

static void sign_with_p256(void)
{
    uint8_t priv[32] = {0};
    uint8_t pub[64] = {0};
    uint8_t data[256] = {0};
    int len = sizeof(data);
    uint8_t sig[64];
    int ret = 1;

    PROFILE_BEGIN
    p256_gen_keypair(priv, pub);
    PROFILE_END("p256_gen_keypair");

    PROFILE_BEGIN
    ret = p256_ecdsa_sign(sig, priv, data, len);
    if (ret != P256_SUCCESS) {
        printf1(TAG_CTAP, "error, p256_ecdsa_sign failed: %d\n", ret);
        assert(1 == 2);
    }
    PROFILE_END("p256_ecdsa_sign");
}

static void sign_stuff(void)
{
    rng_init();

    debug_puts("Signing\n");
    sign_with_mbedtls();
    sign_with_p256();
    debug_puts("Signing done\n");
}
