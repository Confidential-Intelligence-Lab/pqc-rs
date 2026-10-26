// SPDX-License-Identifier: MIT
// Differential oracle for SMAUG-T computeC1.

#include "ciphertext.h"
#include "indcpa.h"
#include "key.h"
#include "params.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static void make_seed(uint8_t seed[32], unsigned int case_id,
                      uint8_t domain) {
    for (unsigned int i = 0; i < 32; ++i) {
        uint8_t value;

        switch (case_id) {
        case 0:
            value = 0;
            break;
        case 1:
            value = 0xff;
            break;
        case 2:
            value = (uint8_t)i;
            break;
        default:
            value = (i & 1U) ? 0x55 : 0xaa;
            break;
        }

        seed[i] = (uint8_t)(value ^ domain);
    }
}

int main(void) {
    for (unsigned int case_id = 0; case_id < 4; ++case_id) {
        uint8_t matrix_seed[32];
        uint8_t ephemeral_seed[32];

        polyvec matrix[SMAUGT_K];
        polyvec ephemeral;
        polyvec c1;

        memset(matrix, 0, sizeof(matrix));
        memset(&ephemeral, 0, sizeof(ephemeral));
        memset(&c1, 0, sizeof(c1));

        make_seed(matrix_seed, case_id, 0x00);
        make_seed(ephemeral_seed, case_id, 0x5a);

        expand_A(matrix, matrix_seed);
        expand_r(&ephemeral, ephemeral_seed);
        computeC1(&c1, matrix, &ephemeral);

        printf("CASE=%u\n", case_id);

        for (unsigned int poly_index = 0;
             poly_index < SMAUGT_K; ++poly_index) {
            printf("POLY=%u", poly_index);

            for (unsigned int index = 0; index < SMAUGT_N; ++index) {
                printf(" %u",
                       (unsigned int)(uint16_t)
                           c1.vec[poly_index].coeffs[index]);
            }

            putchar('\n');
        }
    }

    return 0;
}
