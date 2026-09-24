#define _POSIX_C_SOURCE 200809L

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "crypto/fipsmodule/ml_kem/ml_kem.h"
#include <openssl/evp.h>
#include <openssl/nid.h>

#define SAMPLE_COUNT 100U
#define TARGET_SAMPLE_NS 5000000ULL

#if defined(CLOCK_MONOTONIC_RAW)
#define BENCH_CLOCK CLOCK_MONOTONIC_RAW
#else
#define BENCH_CLOCK CLOCK_MONOTONIC
#endif

static const uint8_t MESSAGE[] =
    "pqc-rfc9958-rs B1.3.5 performance baseline";
static const uint8_t CONTEXT[] = "benchmark";

typedef struct {
    uint8_t kem_seed[MLKEM768_KEYGEN_SEED_LEN];
    uint8_t kem_encaps_seed[MLKEM768_ENCAPS_SEED_LEN];

    uint8_t *kem_public_key;
    uint8_t *kem_secret_key;
    uint8_t *kem_ciphertext;
    uint8_t *kem_shared_secret;

    uint8_t dsa_seed[32];

    uint8_t *dsa_public_key;
    uint8_t *dsa_secret_key;
    uint8_t *dsa_signature;

    size_t dsa_public_key_size;
    size_t dsa_secret_key_size;
    size_t dsa_signature_size;

    volatile uint8_t sink;
} Bench;

typedef int (*bench_fn)(Bench *);

static uint64_t now_ns(void)
{
    struct timespec ts;

    if (clock_gettime(BENCH_CLOCK, &ts) != 0) {
        perror("clock_gettime");
        exit(2);
    }

    return (uint64_t)ts.tv_sec * 1000000000ULL +
           (uint64_t)ts.tv_nsec;
}

/* ============================================================
 * ML-KEM-768
 * ============================================================ */

static int run_kem_keygen(Bench *b)
{
    size_t pk_len = MLKEM768_PUBLIC_KEY_BYTES;
    size_t sk_len = MLKEM768_SECRET_KEY_BYTES;

    int rc = ml_kem_768_keypair_deterministic(
        b->kem_public_key,
        &pk_len,
        b->kem_secret_key,
        &sk_len,
        b->kem_seed
    );

    if (rc != ML_KEM_SUCCESS ||
        pk_len != MLKEM768_PUBLIC_KEY_BYTES ||
        sk_len != MLKEM768_SECRET_KEY_BYTES) {
        return -1;
    }

    b->sink ^= b->kem_public_key[0];
    b->sink ^= b->kem_secret_key[0];

    return 0;
}

static int run_kem_encaps(Bench *b)
{
    size_t ct_len = MLKEM768_CIPHERTEXT_BYTES;
    size_t ss_len = MLKEM768_SHARED_SECRET_LEN;

    int rc = ml_kem_768_encapsulate_deterministic(
        b->kem_ciphertext,
        &ct_len,
        b->kem_shared_secret,
        &ss_len,
        b->kem_public_key,
        b->kem_encaps_seed
    );

    if (rc != ML_KEM_SUCCESS ||
        ct_len != MLKEM768_CIPHERTEXT_BYTES ||
        ss_len != MLKEM768_SHARED_SECRET_LEN) {
        return -1;
    }

    b->sink ^= b->kem_ciphertext[0];
    b->sink ^= b->kem_shared_secret[0];

    return 0;
}

static int run_kem_decaps(Bench *b)
{
    size_t ss_len = MLKEM768_SHARED_SECRET_LEN;

    int rc = ml_kem_768_decapsulate(
        b->kem_shared_secret,
        &ss_len,
        b->kem_ciphertext,
        b->kem_secret_key
    );

    if (rc != ML_KEM_SUCCESS ||
        ss_len != MLKEM768_SHARED_SECRET_LEN) {
        return -1;
    }

    b->sink ^= b->kem_shared_secret[0];

    return 0;
}

/* ============================================================
 * ML-DSA-65
 * ============================================================ */

static int set_signature_context(
    EVP_PKEY_CTX *ctx)
{
    return EVP_PKEY_CTX_set1_signature_context_string(
        ctx,
        CONTEXT,
        sizeof(CONTEXT) - 1U
    );
}

static int generate_dsa_keypair(
    Bench *b,
    uint8_t *pk,
    uint8_t *sk)
{
    EVP_PKEY *pkey = NULL;
    size_t pk_len = b->dsa_public_key_size;
    size_t sk_len = b->dsa_secret_key_size;
    int ok = 0;

    pkey = EVP_PKEY_pqdsa_new_raw_private_key(
        NID_MLDSA65,
        b->dsa_seed,
        sizeof(b->dsa_seed)
    );

    if (pkey == NULL) {
        goto done;
    }

    if (!EVP_PKEY_get_raw_public_key(
            pkey,
            pk,
            &pk_len)) {
        goto done;
    }

    if (!EVP_PKEY_get_raw_private_key(
            pkey,
            sk,
            &sk_len)) {
        goto done;
    }

    if (pk_len != b->dsa_public_key_size ||
        sk_len != b->dsa_secret_key_size) {
        goto done;
    }

    ok = 1;

done:
    EVP_PKEY_free(pkey);
    return ok;
}

static int run_dsa_keygen(Bench *b)
{
    if (!generate_dsa_keypair(
            b,
            b->dsa_public_key,
            b->dsa_secret_key)) {
        return -1;
    }

    b->sink ^= b->dsa_public_key[0];
    b->sink ^= b->dsa_secret_key[0];

    return 0;
}

static int sign_once(
    Bench *b,
    uint8_t *signature,
    size_t *signature_len)
{
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *mdctx = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    size_t out_len = 0;
    int ok = 0;

    pkey = EVP_PKEY_pqdsa_new_raw_private_key(
        NID_MLDSA65,
        b->dsa_secret_key,
        b->dsa_secret_key_size
    );
    if (pkey == NULL) {
        goto done;
    }

    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        goto done;
    }

    if (!EVP_DigestSignInit(
            mdctx,
            &pctx,
            NULL,
            NULL,
            pkey)) {
        goto done;
    }

    if (!set_signature_context(pctx)) {
        goto done;
    }

    if (!EVP_DigestSign(
            mdctx,
            NULL,
            &out_len,
            MESSAGE,
            sizeof(MESSAGE) - 1U)) {
        goto done;
    }

    if (out_len != b->dsa_signature_size) {
        goto done;
    }

    if (!EVP_DigestSign(
            mdctx,
            signature,
            &out_len,
            MESSAGE,
            sizeof(MESSAGE) - 1U)) {
        goto done;
    }

    if (out_len != b->dsa_signature_size) {
        goto done;
    }

    *signature_len = out_len;
    ok = 1;

done:
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);

    return ok;
}

static int run_dsa_sign(Bench *b)
{
    size_t sig_len = 0;

    if (!sign_once(
            b,
            b->dsa_signature,
            &sig_len)) {
        return -1;
    }

    b->sink ^= b->dsa_signature[0];

    return 0;
}

static int run_dsa_verify(Bench *b)
{
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *mdctx = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    int valid;
    int ok = 0;

    pkey = EVP_PKEY_pqdsa_new_raw_public_key(
        NID_MLDSA65,
        b->dsa_public_key,
        b->dsa_public_key_size
    );

    if (pkey == NULL) {
        goto done;
    }

    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        goto done;
    }

    if (!EVP_DigestVerifyInit(
            mdctx,
            &pctx,
            NULL,
            NULL,
            pkey)) {
        goto done;
    }

    if (!set_signature_context(pctx)) {
        goto done;
    }

    valid = EVP_DigestVerify(
        mdctx,
        b->dsa_signature,
        b->dsa_signature_size,
        MESSAGE,
        sizeof(MESSAGE) - 1U
    );

    if (valid != 1) {
        goto done;
    }

    b->sink ^= 1U;
    ok = 1;

done:
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);

    return ok ? 0 : -1;
}

/* ============================================================
 * Benchmark machinery
 * ============================================================ */

static uint64_t measure_iterations(
    Bench *b,
    bench_fn fn,
    uint64_t iterations)
{
    uint64_t start = now_ns();

    for (uint64_t i = 0; i < iterations; ++i) {
        if (fn(b) != 0) {
            fprintf(stderr, "cryptographic operation failed\n");
            exit(3);
        }
    }

    return now_ns() - start;
}

static uint64_t calibrate(
    Bench *b,
    bench_fn fn)
{
    uint64_t iterations = 1;

    for (;;) {
        uint64_t elapsed =
            measure_iterations(b, fn, iterations);

        if (elapsed >= TARGET_SAMPLE_NS) {
            return iterations;
        }

        if (iterations > (1ULL << 30)) {
            fprintf(stderr, "calibration overflow\n");
            exit(4);
        }

        iterations *= 2;
    }
}

static void warm_up(
    Bench *b,
    bench_fn fn)
{
    uint64_t start = now_ns();

    while (now_ns() - start < 3000000000ULL) {
        if (fn(b) != 0) {
            fprintf(stderr, "warm-up operation failed\n");
            exit(5);
        }
    }
}

static void run_benchmark(
    const char *primitive,
    const char *operation,
    Bench *b,
    bench_fn fn)
{
    warm_up(b, fn);

    uint64_t iterations =
        calibrate(b, fn);

    printf("{\n");
    printf("  \"provider\": \"awslc\",\n");
    printf("  \"provider_revision\": "
           "\"add9bcbc8700dc57151e02a627f71df783da49ea\",\n");
    printf("  \"primitive\": \"%s\",\n", primitive);
    printf("  \"operation\": \"%s\",\n", operation);
    printf("  \"samples\": %u,\n", SAMPLE_COUNT);
    printf(
        "  \"iterations_per_sample\": %llu,\n",
        (unsigned long long)iterations
    );
    printf("  \"sample_ns\": [\n");

    for (unsigned int sample = 0;
         sample < SAMPLE_COUNT;
         ++sample) {

        uint64_t elapsed =
            measure_iterations(
                b,
                fn,
                iterations
            );

        double ns =
            (double)elapsed /
            (double)iterations;

        printf(
            "    %.6f%s\n",
            ns,
            sample + 1U == SAMPLE_COUNT
                ? ""
                : ","
        );
    }

    printf("  ],\n");
    printf(
        "  \"sink\": %u\n",
        (unsigned int)b->sink
    );
    printf("}\n");
}

/* ============================================================
 * Setup / cleanup
 * ============================================================ */

static int prepare(Bench *b)
{
    memset(b, 0, sizeof(*b));

    memset(
        b->kem_seed,
        0x33,
        32
    );
    memset(
        b->kem_seed + 32,
        0x44,
        32
    );
    memset(
        b->kem_encaps_seed,
        0x77,
        sizeof(b->kem_encaps_seed)
    );

    b->kem_public_key =
        malloc(MLKEM768_PUBLIC_KEY_BYTES);
    b->kem_secret_key =
        malloc(MLKEM768_SECRET_KEY_BYTES);
    b->kem_ciphertext =
        malloc(MLKEM768_CIPHERTEXT_BYTES);
    b->kem_shared_secret =
        malloc(MLKEM768_SHARED_SECRET_LEN);

    if (b->kem_public_key == NULL ||
        b->kem_secret_key == NULL ||
        b->kem_ciphertext == NULL ||
        b->kem_shared_secret == NULL) {
        fprintf(stderr, "ML-KEM allocation failure\n");
        return 0;
    }

    if (run_kem_keygen(b) != 0 ||
        run_kem_encaps(b) != 0 ||
        run_kem_decaps(b) != 0) {
        fprintf(stderr, "ML-KEM setup failed\n");
        return 0;
    }

    memset(
        b->dsa_seed,
        0x65,
        sizeof(b->dsa_seed)
    );

    b->dsa_public_key_size = 1952U;
    b->dsa_secret_key_size = 4032U;
    b->dsa_signature_size = 3309U;

    b->dsa_public_key =
        malloc(b->dsa_public_key_size);
    b->dsa_secret_key =
        malloc(b->dsa_secret_key_size);
    b->dsa_signature =
        malloc(b->dsa_signature_size);

    if (b->dsa_public_key == NULL ||
        b->dsa_secret_key == NULL ||
        b->dsa_signature == NULL) {
        fprintf(stderr, "ML-DSA allocation failure\n");
        return 0;
    }

    if (run_dsa_keygen(b) != 0) {
        fprintf(stderr, "ML-DSA setup keygen failed\n");
        return 0;
    }

    if (run_dsa_sign(b) != 0) {
        fprintf(stderr, "ML-DSA setup sign failed\n");
        return 0;
    }

    if (run_dsa_verify(b) != 0) {
        fprintf(stderr, "ML-DSA setup verify failed\n");
        return 0;
    }

    return 1;
}

static void cleanup(Bench *b)
{
    free(b->kem_public_key);
    free(b->kem_secret_key);
    free(b->kem_ciphertext);
    free(b->kem_shared_secret);

    free(b->dsa_public_key);
    free(b->dsa_secret_key);
    free(b->dsa_signature);
}

int main(int argc, char **argv)
{
    Bench bench;
    const char *primitive = NULL;
    bench_fn fn = NULL;

    if (argc != 2) {
        fprintf(
            stderr,
            "usage: awslc_bench "
            "{kem-keygen|kem-encaps|kem-decaps|"
            "dsa-keygen|dsa-sign|dsa-verify}\n"
        );
        return 64;
    }

    if (strcmp(argv[1], "kem-keygen") == 0) {
        primitive = "ML-KEM-768";
        fn = run_kem_keygen;
    } else if (strcmp(argv[1], "kem-encaps") == 0) {
        primitive = "ML-KEM-768";
        fn = run_kem_encaps;
    } else if (strcmp(argv[1], "kem-decaps") == 0) {
        primitive = "ML-KEM-768";
        fn = run_kem_decaps;
    } else if (strcmp(argv[1], "dsa-keygen") == 0) {
        primitive = "ML-DSA-65";
        fn = run_dsa_keygen;
    } else if (strcmp(argv[1], "dsa-sign") == 0) {
        primitive = "ML-DSA-65";
        fn = run_dsa_sign;
    } else if (strcmp(argv[1], "dsa-verify") == 0) {
        primitive = "ML-DSA-65";
        fn = run_dsa_verify;
    } else {
        fprintf(
            stderr,
            "unsupported operation: %s\n",
            argv[1]
        );
        return 65;
    }

    if (!prepare(&bench)) {
        cleanup(&bench);
        return 1;
    }

    run_benchmark(
        primitive,
        argv[1],
        &bench,
        fn
    );

    cleanup(&bench);
    return 0;
}
