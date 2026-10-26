// SPDX-License-Identifier: MIT
// Compile with -DSMAUGT_REFERENCE_HWT_C="absolute/path/to/hwt.c".
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#ifndef SMAUGT_REFERENCE_HWT_C
#error "SMAUGT_REFERENCE_HWT_C must name the pinned reference hwt.c"
#endif

// Include the original C implementation in this translation unit so its
// static rej_sample_mod function can be tested without modifying upstream.
#include SMAUGT_REFERENCE_HWT_C

#ifdef SMAUGT_REFERENCE_KEY_C
#include SMAUGT_REFERENCE_KEY_C
#endif

int main(int argc, char **argv) {
    if (argc != 2 && argc != 3) return 2;

    char *end = NULL;
    unsigned long pattern = strtoul(argv[1], &end, 10);
    if (*end != '\0' || pattern > 2) return 2;

    const int ternary_mode =
        argc == 3 && argv[2][0] == 't' && argv[2][1] == '\0';

    const int secret_mode =
        argc == 3 && argv[2][0] == 's' && argv[2][1] == '\0';

    if (argc == 3 && !ternary_mode && !secret_mode) return 2;

    uint8_t seed[34] = {0};
    for (size_t i = 0; i < 32; ++i) {
        seed[i] = pattern == 0 ? 0 :
                  pattern == 1 ? 255 : (uint8_t)i;
    }

    if (secret_mode) {
#ifndef SMAUGT_REFERENCE_KEY_C
        return 2;
#else
        secret_key sk = {0};
        expand_s(&sk, seed);

        for (size_t i = 0; i < SMAUGT_K; ++i) {
            for (size_t j = 0; j < SMAUGT_N; ++j) {
                printf("%s%d",
                       (i == 0 && j == 0) ? "" : ",",
                       (int)sk.vec[i].coeffs[j]);
            }
        }
        putchar('\n');
        return 0;
#endif
    }

    if (ternary_mode) {
        int16_t polynomial[SMAUGT_N] = {0};

        if (hwt(polynomial, seed) != 0) {
            puts("EXHAUSTED");
            return 0;
        }

        for (size_t i = 0; i < SMAUGT_N; ++i) {
            printf("%s%d", i == 0 ? "" : ",", (int)polynomial[i]);
        }
        putchar('\n');
        return 0;
    }

    uint8_t bytes[SMAUGT_HWTSEEDBYTES] = {0};
    uint16_t randomness[SMAUGT_HWTSEEDBYTES / 2] = {0};
    int16_t indices[SMAUGT_N] = {0};

    shake256(bytes, sizeof(bytes), seed, sizeof(seed));
    load16_littleendian(randomness, SMAUGT_HWTSEEDBYTES / 2, bytes);

    if (rej_sample_mod(indices, randomness) != 0) {
        puts("EXHAUSTED");
        return 0;
    }

    for (size_t i = 0; i < SMAUGT_N; ++i) {
        printf("%s%d", i == 0 ? "" : ",", (int)indices[i]);
    }
    putchar('\n');
    return 0;
}
