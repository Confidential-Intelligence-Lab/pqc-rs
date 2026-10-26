// SPDX-License-Identifier: MIT
// Deterministic SMAUG-T KEM keypair reference oracle.

#include "api.h"
#include "params.h"

#include <stdint.h>
#include <stdio.h>

static void print_hex(const uint8_t *data, size_t length) {
    for (size_t i = 0; i < length; ++i) {
        printf("%02x", data[i]);
    }
    putchar('\n');
}

int main(void) {
    for (unsigned int case_id = 0; case_id < 4; ++case_id) {
        uint8_t seed[SMAUGT_CRYPTO_BYTES];
        uint8_t d[SMAUGT_T_BYTES];

        uint8_t pk[SMAUGT_PUBLICKEY_BYTES];
        uint8_t sk[SMAUGT_KEM_SECRETKEY_BYTES];

        for (size_t i = 0; i < sizeof(seed); ++i) {
            seed[i] = (uint8_t)(case_id * 37u + i * 11u + 3u);
        }

        for (size_t i = 0; i < sizeof(d); ++i) {
            d[i] = (uint8_t)(case_id * 53u + i * 7u + 0xa5u);
        }

        if (crypto_kem_keypair_internal(pk, sk, d, seed) != 0) {
            return 1;
        }

        printf("CASE=%u\n", case_id);

        printf("SEED=");
        print_hex(seed, sizeof(seed));

        printf("D=");
        print_hex(d, sizeof(d));

        printf("PK=");
        print_hex(pk, sizeof(pk));

        printf("SK=");
        print_hex(sk, sizeof(sk));
    }

    return 0;
}
