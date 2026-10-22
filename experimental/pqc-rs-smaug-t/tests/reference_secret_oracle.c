// SPDX-License-Identifier: MIT
// Test-only oracle linked against pinned SMAUG-T reference.

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pack.h"

static int hex_digit(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int decode_hex(uint8_t *out, size_t n, const char *hex) {
    if (strlen(hex) != n * 2) return -1;
    for (size_t i = 0; i < n; i++) {
        int hi = hex_digit(hex[2 * i]);
        int lo = hex_digit(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: oracle pack|unpack HEX\n");
        return 2;
    }

    if (strcmp(argv[1], "pack") == 0) {
        uint8_t input[SMAUGT_N];
        uint8_t output[SMAUGT_SKPOLY_BYTES];
        poly p = {0};

        if (decode_hex(input, sizeof(input), argv[2])) return 3;

        for (size_t i = 0; i < SMAUGT_N; i++) {
            if (input[i] > 2) return 4;
            p.coeffs[i] = (int16_t)input[i] - 1;
        }

        pack_s_poly(output, &p);

        for (size_t i = 0; i < sizeof(output); i++)
            printf("%02x", output[i]);
        putchar('\n');
        return 0;
    }

    if (strcmp(argv[1], "unpack") == 0) {
        uint8_t input[SMAUGT_SKPOLY_BYTES];
        poly p = {0};

        if (decode_hex(input, sizeof(input), argv[2])) return 5;

        unpack_s_poly(&p, input);

        for (size_t i = 0; i < SMAUGT_N; i++) {
            if (p.coeffs[i] < -1 || p.coeffs[i] > 1) return 6;
            printf("%d%c", p.coeffs[i],
                   i + 1 == SMAUGT_N ? '\n' : ',');
        }
        return 0;
    }

    return 7;
}
