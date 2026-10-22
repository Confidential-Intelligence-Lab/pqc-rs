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

int main(int argc, char **argv) {
    if (argc != 2) return 2;

    char *end = NULL;
    unsigned long pattern = strtoul(argv[1], &end, 10);
    if (*end != '\0' || pattern > 2) return 2;

    uint8_t seed[34] = {0};
    for (size_t i = 0; i < 32; ++i) {
        seed[i] = pattern == 0 ? 0 :
                  pattern == 1 ? 255 : (uint8_t)i;
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
