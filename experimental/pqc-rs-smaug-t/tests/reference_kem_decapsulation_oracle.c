// SPDX-License-Identifier: MIT
// SMAUG-T 1.1.1 independent KEM decapsulation oracle.
// Test-only C reference; never linked into the Rust crate.

#include "api.h"
#include "params.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static void print_hex(const uint8_t *data, size_t length) {
    for (size_t i = 0; i < length; ++i) {
        printf("%02x", data[i]);
    }
    putchar('\n');
}

int main(void) {
    for (unsigned int case_id = 0; case_id < 4; ++case_id) {
        uint8_t seed[32];
        uint8_t d[SMAUGT_T_BYTES];
        uint8_t mu[SMAUGT_MSG_BYTES];

        uint8_t pk[SMAUGT_PUBLICKEY_BYTES];
        uint8_t sk[SMAUGT_KEM_SECRETKEY_BYTES];
        uint8_t ct[SMAUGT_CIPHERTEXT_BYTES];
        uint8_t tampered[SMAUGT_CIPHERTEXT_BYTES];

        uint8_t ss_enc[SMAUGT_CRYPTO_BYTES];
        uint8_t ss_valid[SMAUGT_CRYPTO_BYTES];
        uint8_t ss_reject[SMAUGT_CRYPTO_BYTES];

        for (size_t i = 0; i < sizeof(seed); ++i) {
            seed[i] = (uint8_t)(case_id * 37u + i * 11u + 3u);
        }

        for (size_t i = 0; i < sizeof(d); ++i) {
            d[i] = (uint8_t)(case_id * 53u + i * 7u + 0xa5u);
        }

        for (size_t i = 0; i < sizeof(mu); ++i) {
            mu[i] = (uint8_t)(case_id * 29u + i * 13u + 0x39u);
        }

        if (crypto_kem_keypair_internal(pk, sk, d, seed) != 0) {
            return 1;
        }

        if (crypto_kem_enc_internal(ct, ss_enc, pk, mu) != 0) {
            return 2;
        }

        if (crypto_kem_dec_internal(ss_valid, ct, sk) != 0) {
            return 3;
        }

        if (memcmp(ss_enc, ss_valid, sizeof(ss_enc)) != 0) {
            return 4;
        }

        memcpy(tampered, ct, sizeof(ct));
        tampered[0] ^= 0x01u;

        if (crypto_kem_dec_internal(ss_reject, tampered, sk) != 0) {
            return 5;
        }

        printf("CASE=%u\n", case_id);

        printf("SEED=");
        print_hex(seed, sizeof(seed));

        printf("D=");
        print_hex(d, sizeof(d));

        printf("MU=");
        print_hex(mu, sizeof(mu));

        printf("CT=");
        print_hex(ct, sizeof(ct));

        printf("SS_VALID=");
        print_hex(ss_valid, sizeof(ss_valid));

        printf("SS_REJECT=");
        print_hex(ss_reject, sizeof(ss_reject));
    }

    return 0;
}
