// SPDX-License-Identifier: MIT
// Differential oracle for SMAUG-T computeC2.

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
        case 0: value = 0; break;
        case 1: value = 0xff; break;
        case 2: value = (uint8_t)i; break;
        default: value = (i & 1U) ? 0x55 : 0xaa; break;
        }
        seed[i] = (uint8_t)(value ^ domain);
    }
}

static void make_message(uint8_t msg[SMAUGT_MSG_BYTES],
                         unsigned int case_id) {
    for (unsigned int i = 0; i < SMAUGT_MSG_BYTES; ++i) {
        switch (case_id) {
        case 0: msg[i] = 0; break;
        case 1: msg[i] = 0xff; break;
        case 2: msg[i] = (uint8_t)i; break;
        default: msg[i] = (i & 1U) ? 0x55 : 0xaa; break;
        }
    }
}

int main(void) {
    for (unsigned int case_id = 0; case_id < 4; ++case_id) {
        uint8_t key_seed[32], ephemeral_seed[32];
        uint8_t message[SMAUGT_MSG_BYTES];

        polyvec matrix[SMAUGT_K], ephemeral, public_vector;
        poly c2;

        memset(matrix, 0, sizeof(matrix));
        memset(&ephemeral, 0, sizeof(ephemeral));
        memset(&public_vector, 0, sizeof(public_vector));
        memset(&c2, 0, sizeof(c2));

        make_seed(key_seed, case_id, 0x00);
        make_seed(ephemeral_seed, case_id, 0x5a);
        make_message(message, case_id);

        expand_A(matrix, key_seed);
        expand_r(&ephemeral, ephemeral_seed);

        // Deterministic canonical public vector in scaled representation.
        for (unsigned int poly_index = 0;
             poly_index < SMAUGT_K; ++poly_index) {
            for (unsigned int index = 0; index < SMAUGT_N; ++index) {
                uint16_t value = (uint16_t)(
                    (index * 17U + poly_index * 31U + case_id * 13U)
                    & ((1U << SMAUGT_LOG_Q) - 1U)
                );
                public_vector.vec[poly_index].coeffs[index] =
                    (int16_t)(value << SMAUGT_MODULUS_16_LOG_Q);
            }
        }

        computeC2(&c2, message, &public_vector, &ephemeral);

        printf("CASE=%u\n", case_id);
        for (unsigned int index = 0; index < SMAUGT_N; ++index) {
            printf("%s%u", index == 0 ? "C2=" : " ",
                   (unsigned int)(uint16_t)c2.coeffs[index]);
        }
        putchar('\n');
    }

    return 0;
}
