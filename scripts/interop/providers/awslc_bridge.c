#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto/fipsmodule/ml_kem/ml_kem.h"

typedef struct {
    const char *name;
    size_t public_key_size;
    size_t secret_key_size;
    size_t ciphertext_size;
    size_t shared_secret_size;
    size_t keygen_seed_size;
    size_t encaps_seed_size;

    int (*keypair_deterministic)(
        uint8_t *, size_t *,
        uint8_t *, size_t *,
        const uint8_t *);

    int (*encapsulate_deterministic)(
        uint8_t *, size_t *,
        uint8_t *, size_t *,
        const uint8_t *,
        const uint8_t *);

    int (*decapsulate)(
        uint8_t *, size_t *,
        const uint8_t *,
        const uint8_t *);
} MlKemParams;

static int get_params(
    const char *name,
    MlKemParams *params)
{
    if (strcmp(name, "ML-KEM-512") == 0) {
        params->name = name;
        params->public_key_size = MLKEM512_PUBLIC_KEY_BYTES;
        params->secret_key_size = MLKEM512_SECRET_KEY_BYTES;
        params->ciphertext_size = MLKEM512_CIPHERTEXT_BYTES;
        params->shared_secret_size = MLKEM512_SHARED_SECRET_LEN;
        params->keygen_seed_size = MLKEM512_KEYGEN_SEED_LEN;
        params->encaps_seed_size = MLKEM512_ENCAPS_SEED_LEN;
        params->keypair_deterministic =
            ml_kem_512_keypair_deterministic;
        params->encapsulate_deterministic =
            ml_kem_512_encapsulate_deterministic;
        params->decapsulate =
            ml_kem_512_decapsulate;
        return 0;
    }

    if (strcmp(name, "ML-KEM-768") == 0) {
        params->name = name;
        params->public_key_size = MLKEM768_PUBLIC_KEY_BYTES;
        params->secret_key_size = MLKEM768_SECRET_KEY_BYTES;
        params->ciphertext_size = MLKEM768_CIPHERTEXT_BYTES;
        params->shared_secret_size = MLKEM768_SHARED_SECRET_LEN;
        params->keygen_seed_size = MLKEM768_KEYGEN_SEED_LEN;
        params->encaps_seed_size = MLKEM768_ENCAPS_SEED_LEN;
        params->keypair_deterministic =
            ml_kem_768_keypair_deterministic;
        params->encapsulate_deterministic =
            ml_kem_768_encapsulate_deterministic;
        params->decapsulate =
            ml_kem_768_decapsulate;
        return 0;
    }

    if (strcmp(name, "ML-KEM-1024") == 0) {
        params->name = name;
        params->public_key_size = MLKEM1024_PUBLIC_KEY_BYTES;
        params->secret_key_size = MLKEM1024_SECRET_KEY_BYTES;
        params->ciphertext_size = MLKEM1024_CIPHERTEXT_BYTES;
        params->shared_secret_size = MLKEM1024_SHARED_SECRET_LEN;
        params->keygen_seed_size = MLKEM1024_KEYGEN_SEED_LEN;
        params->encaps_seed_size = MLKEM1024_ENCAPS_SEED_LEN;
        params->keypair_deterministic =
            ml_kem_1024_keypair_deterministic;
        params->encapsulate_deterministic =
            ml_kem_1024_encapsulate_deterministic;
        params->decapsulate =
            ml_kem_1024_decapsulate;
        return 0;
    }

    fprintf(
        stderr,
        "unsupported parameter set: %s\n",
        name);
    return -1;
}

static uint8_t *from_hex(
    const char *hex,
    size_t expected_len)
{
    uint8_t *out;
    size_t i;

    if (hex == NULL ||
        strlen(hex) != expected_len * 2U) {
        return NULL;
    }

    out = malloc(expected_len == 0U ? 1U : expected_len);
    if (out == NULL) {
        return NULL;
    }

    for (i = 0; i < expected_len; i++) {
        unsigned int value;

        if (sscanf(
                hex + (2U * i),
                "%2x",
                &value) != 1) {
            free(out);
            return NULL;
        }

        out[i] = (uint8_t)value;
    }

    return out;
}

static void print_hex(
    const char *name,
    const uint8_t *data,
    size_t len)
{
    size_t i;

    printf("%s=", name);
    for (i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

static int kem_keygen(
    const MlKemParams *params,
    const char *d_hex,
    const char *z_hex)
{
    uint8_t *d = NULL;
    uint8_t *z = NULL;
    uint8_t *public_key = NULL;
    uint8_t *secret_key = NULL;
    uint8_t seed[64];
    size_t public_len;
    size_t secret_len;
    int rc = 1;

    if (params->keygen_seed_size != sizeof(seed)) {
        fprintf(stderr, "unexpected keygen seed size\n");
        return 1;
    }

    d = from_hex(d_hex, 32U);
    z = from_hex(z_hex, 32U);

    if (d == NULL || z == NULL) {
        fprintf(stderr, "d and z must each be 32 bytes\n");
        goto cleanup;
    }

    memcpy(seed, d, 32U);
    memcpy(seed + 32U, z, 32U);

    public_key = malloc(params->public_key_size);
    secret_key = malloc(params->secret_key_size);

    if (public_key == NULL || secret_key == NULL) {
        fprintf(stderr, "allocation failure\n");
        goto cleanup;
    }

    public_len = params->public_key_size;
    secret_len = params->secret_key_size;

    rc = params->keypair_deterministic(
        public_key,
        &public_len,
        secret_key,
        &secret_len,
        seed);

    if (rc != ML_KEM_SUCCESS) {
        fprintf(
            stderr,
            "AWS-LC deterministic keygen failed: %d\n",
            rc);
        rc = 1;
        goto cleanup;
    }

    if (public_len != params->public_key_size ||
        secret_len != params->secret_key_size) {
        fprintf(stderr, "AWS-LC returned unexpected key lengths\n");
        rc = 1;
        goto cleanup;
    }

    print_hex("public_key", public_key, public_len);
    print_hex("secret_key", secret_key, secret_len);

    rc = 0;

cleanup:
    free(d);
    free(z);
    free(public_key);
    free(secret_key);
    return rc;
}

static int kem_encaps(
    const MlKemParams *params,
    const char *public_key_hex,
    const char *m_hex)
{
    uint8_t *public_key = NULL;
    uint8_t *m = NULL;
    uint8_t *ciphertext = NULL;
    uint8_t *shared_secret = NULL;
    size_t ciphertext_len;
    size_t shared_secret_len;
    int rc = 1;

    public_key = from_hex(
        public_key_hex,
        params->public_key_size);

    m = from_hex(
        m_hex,
        params->encaps_seed_size);

    if (public_key == NULL || m == NULL) {
        fprintf(stderr, "invalid encapsulation input\n");
        goto cleanup;
    }

    ciphertext = malloc(params->ciphertext_size);
    shared_secret = malloc(params->shared_secret_size);

    if (ciphertext == NULL || shared_secret == NULL) {
        fprintf(stderr, "allocation failure\n");
        goto cleanup;
    }

    ciphertext_len = params->ciphertext_size;
    shared_secret_len = params->shared_secret_size;

    rc = params->encapsulate_deterministic(
        ciphertext,
        &ciphertext_len,
        shared_secret,
        &shared_secret_len,
        public_key,
        m);

    if (rc != ML_KEM_SUCCESS) {
        fprintf(
            stderr,
            "AWS-LC deterministic encapsulation failed: %d\n",
            rc);
        rc = 1;
        goto cleanup;
    }

    if (ciphertext_len != params->ciphertext_size ||
        shared_secret_len != params->shared_secret_size) {
        fprintf(
            stderr,
            "AWS-LC returned unexpected encapsulation lengths\n");
        rc = 1;
        goto cleanup;
    }

    print_hex(
        "ciphertext",
        ciphertext,
        ciphertext_len);

    print_hex(
        "shared_secret",
        shared_secret,
        shared_secret_len);

    rc = 0;

cleanup:
    free(public_key);
    free(m);
    free(ciphertext);
    free(shared_secret);
    return rc;
}

static int kem_decaps(
    const MlKemParams *params,
    const char *secret_key_hex,
    const char *ciphertext_hex)
{
    uint8_t *secret_key = NULL;
    uint8_t *ciphertext = NULL;
    uint8_t *shared_secret = NULL;
    size_t shared_secret_len;
    int rc = 1;

    secret_key = from_hex(
        secret_key_hex,
        params->secret_key_size);

    ciphertext = from_hex(
        ciphertext_hex,
        params->ciphertext_size);

    if (secret_key == NULL || ciphertext == NULL) {
        fprintf(stderr, "invalid decapsulation input\n");
        goto cleanup;
    }

    shared_secret = malloc(params->shared_secret_size);
    if (shared_secret == NULL) {
        fprintf(stderr, "allocation failure\n");
        goto cleanup;
    }

    shared_secret_len = params->shared_secret_size;

    rc = params->decapsulate(
        shared_secret,
        &shared_secret_len,
        ciphertext,
        secret_key);

    if (rc != ML_KEM_SUCCESS) {
        fprintf(
            stderr,
            "AWS-LC decapsulation failed: %d\n",
            rc);
        rc = 1;
        goto cleanup;
    }

    if (shared_secret_len != params->shared_secret_size) {
        fprintf(
            stderr,
            "AWS-LC returned unexpected shared-secret length\n");
        rc = 1;
        goto cleanup;
    }

    print_hex(
        "shared_secret",
        shared_secret,
        shared_secret_len);

    rc = 0;

cleanup:
    free(secret_key);
    free(ciphertext);
    free(shared_secret);
    return rc;
}

int main(int argc, char **argv)
{
    MlKemParams params;

    if (argc < 3) {
        fprintf(
            stderr,
            "usage: awslc_bridge OP PARAMETER_SET [ARGS]\n");
        return 64;
    }

    if (get_params(argv[2], &params) != 0) {
        return 65;
    }

    if (strcmp(argv[1], "kem-keygen") == 0) {
        if (argc != 5) return 64;

        return kem_keygen(
            &params,
            argv[3],
            argv[4]);
    }

    if (strcmp(argv[1], "kem-encaps") == 0) {
        if (argc != 5) return 64;

        return kem_encaps(
            &params,
            argv[3],
            argv[4]);
    }

    if (strcmp(argv[1], "kem-decaps") == 0) {
        if (argc != 5) return 64;

        return kem_decaps(
            &params,
            argv[3],
            argv[4]);
    }

    fprintf(
        stderr,
        "unsupported operation: %s\n",
        argv[1]);
    return 66;
}
