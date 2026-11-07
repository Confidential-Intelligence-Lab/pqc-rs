// SPDX-License-Identifier: MIT
// Test-only decoding oracle linked against pinned SMAUG-T reference.

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "params.h"
#include "poly.h"
#include "packring.h"
#include "pack.h"

static int read_hex(uint8_t *out, size_t length, const char *hex) {
    if (strlen(hex) != length * 2) return -1;

    for (size_t i = 0; i < length; i++) {
        unsigned value;
        if (sscanf(hex + 2 * i, "%2x", &value) != 1) return -1;
        out[i] = (uint8_t)value;
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: oracle WIDTH HEX\n");
        return 2;
    }

    unsigned width = (unsigned)strtoul(argv[1], NULL, 10);

    if (width < 3 || width > 11) return 3;

    size_t length = SMAUGT_N * width / 8u;
    uint8_t bytes[352] = {0};
    poly p = {0};

    if (read_hex(bytes, length, argv[2]) != 0) return 4;

    if (width == SMAUGT_LOG_Q) {
        UNPACK_RING(SMAUGT_LOG_Q)(&p, bytes);
    } else if (width == SMAUGT_LOG_P) {
        UNPACK_RING(SMAUGT_LOG_P)(&p, bytes);
    } else if (width == SMAUGT_LOG_P_PRIME) {
        UNPACK_RING(SMAUGT_LOG_P_PRIME)(&p, bytes);
    } else {
        return 5;
    }

    for (size_t i = 0; i < SMAUGT_N; i++) {
        uint16_t value = (uint16_t)p.coeffs[i];

        if (width == SMAUGT_LOG_Q) {
            value >>= 16u - SMAUGT_LOG_Q;
        }

        printf("%u%c", (unsigned)value,
               i + 1 == SMAUGT_N ? '\n' : ',');
    }

    return 0;
}
