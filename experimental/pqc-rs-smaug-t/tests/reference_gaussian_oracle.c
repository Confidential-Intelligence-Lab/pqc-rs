// SPDX-License-Identifier: MIT
// Differential oracle for the pinned SMAUG-T 1.1.1 Gaussian sampler.
//
// Usage: oracle PATTERN [p|v]
//   p: one polynomial, domain byte 0
//   v: complete Gaussian vector, domain byte K*i
//
// Compile against the pinned reference dg.c and fips202.c.

#include "dg.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void print_poly(const poly *p, int *first) {
    for (size_t j = 0; j < SMAUGT_N; ++j) {
        printf("%s%d", *first ? "" : ",", (int)p->coeffs[j]);
        *first = 0;
    }
}

int main(int argc, char **argv) {
    if (argc != 2 && argc != 3) return 2;

    char *end = NULL;
    unsigned long pattern = strtoul(argv[1], &end, 10);

    if (*end != '\0' || pattern > 2) return 2;

    const char *mode = argc == 3 ? argv[2] : "p";

    if (strcmp(mode, "p") != 0 && strcmp(mode, "v") != 0)
        return 2;

    uint8_t seed[SMAUGT_CRYPTO_BYTES] = {0};

    for (size_t i = 0; i < sizeof(seed); ++i) {
        seed[i] = pattern == 0 ? 0 :
                  pattern == 1 ? 255 : (uint8_t)i;
    }

    int first = 1;

    if (strcmp(mode, "p") == 0) {
        uint8_t extended[SMAUGT_CRYPTO_BYTES + 1] = {0};
        poly result = {0};

        memcpy(extended, seed, sizeof(seed));

        if (d_gaussian_poly(&result, extended) != 0)
            return 1;

        print_poly(&result, &first);
    } else {
        polyvec result = {0};

        d_gaussian(&result, seed);

        for (size_t i = 0; i < SMAUGT_K; ++i)
            print_poly(&result.vec[i], &first);
    }

    putchar('\n');
    return 0;
}
