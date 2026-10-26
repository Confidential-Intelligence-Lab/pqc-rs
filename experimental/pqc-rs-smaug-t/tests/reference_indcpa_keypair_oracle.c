// SPDX-License-Identifier: MIT
// Deterministic SMAUG-T IND-CPA keypair reference oracle.

#include "indcpa.h"
#include "params.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

static void print_hex(const uint8_t *bytes, size_t length) {
    for (size_t i = 0; i < length; ++i)
        printf("%02x", bytes[i]);
    putchar('\n');
}

int main(void) {
    uint8_t seed[SMAUGT_CRYPTO_BYTES];
    uint8_t pk[SMAUGT_PUBLICKEY_BYTES];
    uint8_t sk[SMAUGT_PKE_SECRETKEY_BYTES];

    for (unsigned int pattern = 0; pattern < 4; ++pattern) {
        for (size_t i = 0; i < sizeof(seed); ++i) {
            switch (pattern) {
            case 0:
                seed[i] = 0;
                break;
            case 1:
                seed[i] = 0xff;
                break;
            case 2:
                seed[i] = (uint8_t)i;
                break;
            default:
                seed[i] = (i & 1) ? 0x55 : 0xaa;
                break;
            }
        }

        indcpa_keypair(pk, sk, seed);

        printf("CASE=%u\n", pattern);
        printf("PK=");
        print_hex(pk, sizeof(pk));
        printf("SK=");
        print_hex(sk, sizeof(sk));
    }

    return 0;
}
