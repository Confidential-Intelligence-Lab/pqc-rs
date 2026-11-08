// SPDX-License-Identifier: MIT
// Deterministic IND-CPA encryption oracle for SMAUG-T 1.1.1.

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "indcpa.h"
#include "params.h"

static void make_pattern(uint8_t *output, size_t length,
                         unsigned int case_id, uint8_t domain) {
    for (size_t i = 0; i < length; ++i) {
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

        output[i] = (uint8_t)(value ^ domain);
    }
}

static void print_hex(const char *label, const uint8_t *bytes, size_t length) {
    printf("%s=", label);

    for (size_t i = 0; i < length; ++i)
        printf("%02x", (unsigned int)bytes[i]);

    putchar('\n');
}

int main(void) {
    for (unsigned int case_id = 0; case_id < 4; ++case_id) {
        uint8_t key_seed[SMAUGT_CRYPTO_BYTES];
        uint8_t encryption_seed[SMAUGT_DELTA_BYTES];
        uint8_t message[SMAUGT_MSG_BYTES];

        uint8_t pk[SMAUGT_PUBLICKEY_BYTES];
        uint8_t sk[SMAUGT_PKE_SECRETKEY_BYTES];
        uint8_t ct[SMAUGT_CIPHERTEXT_BYTES];

        make_pattern(key_seed, sizeof(key_seed), case_id, 0x11);
        make_pattern(encryption_seed, sizeof(encryption_seed), case_id, 0x5a);
        make_pattern(message, sizeof(message), case_id, 0x00);

        indcpa_keypair(pk, sk, key_seed);
        indcpa_enc(ct, pk, message, encryption_seed);

        printf("CASE=%u\n", case_id);
        print_hex("PK", pk, sizeof(pk));
        print_hex("CT", ct, sizeof(ct));
    }

    return 0;
}
