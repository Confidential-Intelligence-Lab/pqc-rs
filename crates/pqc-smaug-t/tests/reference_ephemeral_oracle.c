// SPDX-License-Identifier: MIT
// Deterministic SMAUG-T ExpandR reference oracle.

#include "indcpa.h"
#include "params.h"
#include "poly.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static void make_seed(uint8_t seed[SMAUGT_DELTA_BYTES], unsigned int test_case) {
    for (unsigned int i = 0; i < SMAUGT_DELTA_BYTES; ++i) {
        switch (test_case) {
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
            seed[i] = (i & 1u) ? 0x55 : 0xaa;
            break;
        }
    }
}

int main(void) {
    for (unsigned int test_case = 0; test_case < 4; ++test_case) {
        uint8_t seed[SMAUGT_DELTA_BYTES];
        polyvec r;

        make_seed(seed, test_case);
        memset(&r, 0, sizeof(r));
        expand_r(&r, seed);

        printf("CASE=%u\n", test_case);

        for (unsigned int k = 0; k < SMAUGT_K; ++k) {
            printf("POLY=%u", k);

            for (unsigned int i = 0; i < SMAUGT_N; ++i) {
                printf(" %d", (int)(int16_t)r.vec[k].coeffs[i]);
            }

            putchar('\n');
        }
    }

    return 0;
}
