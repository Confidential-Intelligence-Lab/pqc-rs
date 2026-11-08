// SPDX-License-Identifier: MIT
// Test-only oracle using the pinned SMAUG-T reference implementation.

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "params.h"
#include "poly.h"
#include "packring.h"

static void fill_poly(poly *p, unsigned width, unsigned seed) {
    uint16_t mask = (uint16_t)((1u << width) - 1u);

    for (unsigned i = 0; i < SMAUGT_N; i++) {
        uint32_t x = (uint32_t)i * 73u + seed * 19u;
        uint16_t coefficient = (uint16_t)(x & mask);

        // R_q coefficients use the reference's scaled 16-bit
        // representation. R_p and R_p' coefficients do not.
        if (width == SMAUGT_LOG_Q) {
            coefficient = (uint16_t)(
                coefficient << (16u - SMAUGT_LOG_Q)
            );
        }

        p->coeffs[i] = (int16_t)coefficient;
    }
}

static void print_hex(const uint8_t *bytes, size_t length) {
    for (size_t i = 0; i < length; i++) {
        printf("%02x", bytes[i]);
    }
    putchar('\n');
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: oracle WIDTH SEED\n");
        return 2;
    }

    unsigned width = (unsigned)strtoul(argv[1], NULL, 10);
    unsigned seed = (unsigned)strtoul(argv[2], NULL, 10);

    poly p;
    uint8_t bytes[352] = {0};

    fill_poly(&p, width, seed);

    size_t length = (SMAUGT_N * width) / 8u;

    if (width == SMAUGT_LOG_Q) {
        PACK_RING(SMAUGT_LOG_Q)(bytes, &p);
    } else if (width == SMAUGT_LOG_P) {
        PACK_RING(SMAUGT_LOG_P)(bytes, &p);
    } else if (width == SMAUGT_LOG_P_PRIME) {
        PACK_RING(SMAUGT_LOG_P_PRIME)(bytes, &p);
    } else {
        fprintf(stderr, "unsupported width for this mode\n");
        return 3;
    }

    print_hex(bytes, length);
    return 0;
}
