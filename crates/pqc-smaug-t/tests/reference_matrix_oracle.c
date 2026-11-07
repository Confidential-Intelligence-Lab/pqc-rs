// SPDX-License-Identifier: MIT
// Independent test harness using pinned SMAUG-T C primitives.

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "params.h"
#include "poly.h"
#include "fips202.h"
#include "packring.h"

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: reference_matrix_oracle SEED_PATTERN\n");
        return 2;
    }

    char *end = NULL;
    long pattern = strtol(argv[1], &end, 10);

    if (*argv[1] == '\0' || *end != '\0' ||
        pattern < 0 || pattern > 2) {
        fprintf(stderr, "Invalid seed pattern\n");
        return 2;
    }

    uint8_t seed[SMAUGT_PKSEED_BYTES];

    for (size_t i = 0; i < sizeof(seed); ++i) {
        seed[i] = pattern == 0 ? 0 :
                  pattern == 1 ? 255 : (uint8_t)i;
    }

    uint8_t input[SMAUGT_PKSEED_BYTES + 2];
    memcpy(input, seed, sizeof(seed));

    uint8_t packed[SMAUGT_PKPOLY_BYTES];
    poly decoded;

    for (unsigned int row = 0; row < SMAUGT_K; ++row) {
        for (unsigned int column = 0; column < SMAUGT_K; ++column) {
            input[SMAUGT_PKSEED_BYTES] = (uint8_t)row;
            input[SMAUGT_PKSEED_BYTES + 1] = (uint8_t)column;

            shake128(
                packed,
                sizeof(packed),
                input,
                sizeof(input)
            );

            UNPACK_RING(SMAUGT_LOG_Q)(&decoded, packed);

            for (unsigned int i = 0; i < SMAUGT_N; ++i) {
                // The reference stores q-domain coefficients scaled
                // into 16-bit representation.
                uint16_t canonical =
                    (uint16_t)decoded.coeffs[i] >>
                    (16 - SMAUGT_LOG_Q);

                printf("%u", (unsigned int)canonical);

                if (i + 1 != SMAUGT_N) {
                    putchar(',');
                }
            }

            putchar('\n');
        }
    }

    return 0;
}
