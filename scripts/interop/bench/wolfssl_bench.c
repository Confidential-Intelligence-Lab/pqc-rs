#define _POSIX_C_SOURCE 200809L

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/wc_mlkem.h>
#include <wolfssl/wolfcrypt/wc_mldsa.h>

#define SAMPLE_COUNT 100U
#define TARGET_SAMPLE_NS 5000000ULL

#if defined(CLOCK_MONOTONIC_RAW)
#define BENCH_CLOCK CLOCK_MONOTONIC_RAW
#else
#define BENCH_CLOCK CLOCK_MONOTONIC
#endif

static const unsigned char MESSAGE[] =
    "pqc-rfc9958-rs B1.3.5 performance baseline";

static const unsigned char CONTEXT[] =
    "benchmark";

typedef struct {
    /* ML-KEM-768 */
    word32 kem_public_key_size;
    word32 kem_private_key_size;
    word32 kem_ciphertext_size;
    word32 kem_shared_secret_size;

    unsigned char *kem_public_key;
    unsigned char *kem_private_key;
    unsigned char *kem_ciphertext;
    unsigned char *kem_shared_secret;

    unsigned char kem_keygen_random[
        WC_ML_KEM_MAKEKEY_RAND_SZ
    ];
    unsigned char kem_encaps_random[
        WC_ML_KEM_ENC_RAND_SZ
    ];

    /* ML-DSA-65 */
    unsigned char dsa_seed[32];
    unsigned char dsa_randomness[32];

    unsigned char *dsa_public_key;
    unsigned char *dsa_private_key;
    unsigned char *dsa_signature;

    word32 dsa_public_key_size;
    word32 dsa_private_key_size;
    word32 dsa_signature_size;

    volatile unsigned char sink;
} Bench;

typedef int (*bench_fn)(Bench *);

static uint64_t now_ns(void)
{
    struct timespec ts;

    if (clock_gettime(BENCH_CLOCK, &ts) != 0) {
        perror("clock_gettime");
        exit(2);
    }

    return ((uint64_t)ts.tv_sec * 1000000000ULL) +
           (uint64_t)ts.tv_nsec;
}

/* ============================================================
 * ML-KEM helpers
 * ============================================================ */

static int init_kem(MlKemKey *key)
{
    return wc_MlKemKey_Init(
        key,
        WC_ML_KEM_768,
        NULL,
        INVALID_DEVID
    );
}

static int query_kem_sizes(Bench *b)
{
    MlKemKey key;
    int initialized = 0;
    int rc;

    rc = init_kem(&key);
    if (rc != 0) {
        return rc;
    }
    initialized = 1;

    rc = wc_MlKemKey_PublicKeySize(
        &key,
        &b->kem_public_key_size
    );
    if (rc != 0) goto done;

    rc = wc_MlKemKey_PrivateKeySize(
        &key,
        &b->kem_private_key_size
    );
    if (rc != 0) goto done;

    rc = wc_MlKemKey_CipherTextSize(
        &key,
        &b->kem_ciphertext_size
    );
    if (rc != 0) goto done;

    rc = wc_MlKemKey_SharedSecretSize(
        &key,
        &b->kem_shared_secret_size
    );

done:
    if (initialized) {
        (void)wc_MlKemKey_Free(&key);
    }

    return rc;
}

static int run_kem_keygen(Bench *b)
{
    MlKemKey key;
    int initialized = 0;
    int rc;

    rc = init_kem(&key);
    if (rc != 0) {
        return rc;
    }
    initialized = 1;

    rc = wc_MlKemKey_MakeKeyWithRandom(
        &key,
        b->kem_keygen_random,
        (int)sizeof(b->kem_keygen_random)
    );
    if (rc != 0) goto done;

    rc = wc_MlKemKey_EncodePublicKey(
        &key,
        b->kem_public_key,
        b->kem_public_key_size
    );
    if (rc != 0) goto done;

    rc = wc_MlKemKey_EncodePrivateKey(
        &key,
        b->kem_private_key,
        b->kem_private_key_size
    );
    if (rc != 0) goto done;

    b->sink ^= b->kem_public_key[0];
    b->sink ^= b->kem_private_key[0];

done:
    if (initialized) {
        (void)wc_MlKemKey_Free(&key);
    }

    return rc;
}

static int run_kem_encaps(Bench *b)
{
    MlKemKey key;
    int initialized = 0;
    int rc;

    rc = init_kem(&key);
    if (rc != 0) {
        return rc;
    }
    initialized = 1;

    rc = wc_MlKemKey_DecodePublicKey(
        &key,
        b->kem_public_key,
        b->kem_public_key_size
    );
    if (rc != 0) goto done;

    rc = wc_MlKemKey_EncapsulateWithRandom(
        &key,
        b->kem_ciphertext,
        b->kem_shared_secret,
        b->kem_encaps_random,
        WC_ML_KEM_ENC_RAND_SZ
    );
    if (rc != 0) goto done;

    b->sink ^= b->kem_ciphertext[0];
    b->sink ^= b->kem_shared_secret[0];

done:
    if (initialized) {
        (void)wc_MlKemKey_Free(&key);
    }

    return rc;
}

static int run_kem_decaps(Bench *b)
{
    MlKemKey key;
    int initialized = 0;
    int rc;

    rc = init_kem(&key);
    if (rc != 0) {
        return rc;
    }
    initialized = 1;

    rc = wc_MlKemKey_DecodePrivateKey(
        &key,
        b->kem_private_key,
        b->kem_private_key_size
    );
    if (rc != 0) goto done;

    rc = wc_MlKemKey_Decapsulate(
        &key,
        b->kem_shared_secret,
        b->kem_ciphertext,
        b->kem_ciphertext_size
    );
    if (rc != 0) goto done;

    b->sink ^= b->kem_shared_secret[0];

done:
    if (initialized) {
        (void)wc_MlKemKey_Free(&key);
    }

    return rc;
}

/* ============================================================
 * ML-DSA helpers
 * ============================================================ */

static int init_dsa(wc_MlDsaKey *key)
{
    int rc;

    rc = wc_MlDsaKey_Init(
        key,
        NULL,
        INVALID_DEVID
    );
    if (rc != 0) {
        return rc;
    }

    rc = wc_MlDsaKey_SetParams(
        key,
        WC_ML_DSA_65
    );

    if (rc != 0) {
        wc_MlDsaKey_Free(key);
        return rc;
    }

    return 0;
}

static int run_dsa_keygen(Bench *b)
{
    wc_MlDsaKey key;
    word32 pub_len;
    word32 priv_len;
    int initialized = 0;
    int rc;

    rc = init_dsa(&key);
    if (rc != 0) {
        return rc;
    }
    initialized = 1;

    rc = wc_MlDsaKey_MakeKeyFromSeed(
        &key,
        b->dsa_seed
    );
    if (rc != 0) goto done;

    pub_len = b->dsa_public_key_size;

    rc = wc_MlDsaKey_ExportPubRaw(
        &key,
        b->dsa_public_key,
        &pub_len
    );
    if (rc != 0) goto done;

    priv_len = b->dsa_private_key_size;

    rc = wc_MlDsaKey_ExportPrivRaw(
        &key,
        b->dsa_private_key,
        &priv_len
    );
    if (rc != 0) goto done;

    if (pub_len != b->dsa_public_key_size ||
        priv_len != b->dsa_private_key_size) {
        rc = -1;
        goto done;
    }

    b->sink ^= b->dsa_public_key[0];
    b->sink ^= b->dsa_private_key[0];

done:
    if (initialized) {
        wc_MlDsaKey_Free(&key);
    }

    return rc;
}

static int run_dsa_sign(Bench *b)
{
    wc_MlDsaKey key;
    word32 signature_len;
    int initialized = 0;
    int rc;

    rc = init_dsa(&key);
    if (rc != 0) {
        return rc;
    }
    initialized = 1;

    rc = wc_MlDsaKey_ImportPrivRaw(
        &key,
        b->dsa_private_key,
        b->dsa_private_key_size
    );
    if (rc != 0) goto done;

    signature_len = b->dsa_signature_size;

    rc = wc_MlDsaKey_SignCtxWithSeed(
        &key,
        CONTEXT,
        (byte)(sizeof(CONTEXT) - 1U),
        b->dsa_signature,
        &signature_len,
        MESSAGE,
        (word32)(sizeof(MESSAGE) - 1U),
        b->dsa_randomness
    );
    if (rc != 0) goto done;

    if (signature_len != b->dsa_signature_size) {
        rc = -1;
        goto done;
    }

    b->sink ^= b->dsa_signature[0];

done:
    if (initialized) {
        wc_MlDsaKey_Free(&key);
    }

    return rc;
}

static int run_dsa_verify(Bench *b)
{
    wc_MlDsaKey key;
    int initialized = 0;
    int verify_result = 0;
    int rc;

    rc = init_dsa(&key);
    if (rc != 0) {
        return rc;
    }
    initialized = 1;

    rc = wc_MlDsaKey_ImportPubRaw(
        &key,
        b->dsa_public_key,
        b->dsa_public_key_size
    );
    if (rc != 0) goto done;

    rc = wc_MlDsaKey_VerifyCtx(
        &key,
        b->dsa_signature,
        b->dsa_signature_size,
        CONTEXT,
        (byte)(sizeof(CONTEXT) - 1U),
        MESSAGE,
        (word32)(sizeof(MESSAGE) - 1U),
        &verify_result
    );
    if (rc != 0) goto done;

    if (verify_result != 1) {
        rc = -1;
        goto done;
    }

    b->sink ^= 1U;

done:
    if (initialized) {
        wc_MlDsaKey_Free(&key);
    }

    return rc;
}

/* ============================================================
 * Benchmark machinery
 * ============================================================ */

static uint64_t measure_iterations(
    Bench *b,
    bench_fn fn,
    uint64_t iterations
)
{
    uint64_t start = now_ns();

    for (uint64_t i = 0; i < iterations; ++i) {
        if (fn(b) != 0) {
            fprintf(
                stderr,
                "cryptographic operation failed\n"
            );
            exit(3);
        }
    }

    return now_ns() - start;
}

static uint64_t calibrate(
    Bench *b,
    bench_fn fn
)
{
    uint64_t iterations = 1;

    for (;;) {
        uint64_t elapsed =
            measure_iterations(
                b,
                fn,
                iterations
            );

        if (elapsed >= TARGET_SAMPLE_NS) {
            return iterations;
        }

        if (iterations > (1ULL << 30)) {
            fprintf(
                stderr,
                "calibration overflow\n"
            );
            exit(4);
        }

        iterations *= 2;
    }
}

static void warm_up(
    Bench *b,
    bench_fn fn
)
{
    uint64_t start = now_ns();

    while (now_ns() - start <
           3000000000ULL) {
        if (fn(b) != 0) {
            fprintf(
                stderr,
                "warm-up operation failed\n"
            );
            exit(5);
        }
    }
}

static void run_benchmark(
    const char *primitive,
    const char *operation,
    Bench *b,
    bench_fn fn
)
{
    uint64_t iterations;

    warm_up(b, fn);
    iterations = calibrate(b, fn);

    printf("{\n");
    printf(
        "  \"provider\": \"wolfssl\",\n"
    );
    printf(
        "  \"provider_version\": \"5.9.2\",\n"
    );
    printf(
        "  \"primitive\": \"%s\",\n",
        primitive
    );
    printf(
        "  \"operation\": \"%s\",\n",
        operation
    );
    printf(
        "  \"samples\": %u,\n",
        SAMPLE_COUNT
    );
    printf(
        "  \"iterations_per_sample\": %llu,\n",
        (unsigned long long)iterations
    );
    printf(
        "  \"sample_ns\": [\n"
    );

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
    int rc;

    memset(b, 0, sizeof(*b));

    /*
     * ML-KEM-768 deterministic inputs:
     * d = 0x33*32
     * z = 0x44*32
     * m = 0x77*32
     */
    memset(
        b->kem_keygen_random,
        0,
        sizeof(b->kem_keygen_random)
    );

    memset(
        b->kem_keygen_random,
        0x33,
        WC_ML_KEM_SYM_SZ
    );

    memset(
        b->kem_keygen_random +
            WC_ML_KEM_SYM_SZ,
        0x44,
        WC_ML_KEM_SYM_SZ
    );

    memset(
        b->kem_encaps_random,
        0x77,
        sizeof(b->kem_encaps_random)
    );

    rc = query_kem_sizes(b);
    if (rc != 0) {
        fprintf(
            stderr,
            "ML-KEM size query failed: %d\n",
            rc
        );
        return 0;
    }

    b->kem_public_key =
        malloc(b->kem_public_key_size);
    b->kem_private_key =
        malloc(b->kem_private_key_size);
    b->kem_ciphertext =
        malloc(b->kem_ciphertext_size);
    b->kem_shared_secret =
        malloc(b->kem_shared_secret_size);

    if (b->kem_public_key == NULL ||
        b->kem_private_key == NULL ||
        b->kem_ciphertext == NULL ||
        b->kem_shared_secret == NULL) {
        fprintf(
            stderr,
            "ML-KEM allocation failure\n"
        );
        return 0;
    }

    if (run_kem_keygen(b) != 0) {
        fprintf(
            stderr,
            "ML-KEM setup keygen failed\n"
        );
        return 0;
    }

    if (run_kem_encaps(b) != 0) {
        fprintf(
            stderr,
            "ML-KEM setup encaps failed\n"
        );
        return 0;
    }

    /*
     * ML-DSA-65 deterministic inputs.
     */
    memset(
        b->dsa_seed,
        0x65,
        sizeof(b->dsa_seed)
    );

    memset(
        b->dsa_randomness,
        0x00,
        sizeof(b->dsa_randomness)
    );

    b->dsa_public_key_size =
        WC_MLDSA_65_PUB_KEY_SIZE;

    b->dsa_private_key_size =
        WC_MLDSA_65_KEY_SIZE;

    b->dsa_signature_size =
        WC_MLDSA_65_SIG_SIZE;

    b->dsa_public_key =
        malloc(b->dsa_public_key_size);

    b->dsa_private_key =
        malloc(b->dsa_private_key_size);

    b->dsa_signature =
        malloc(b->dsa_signature_size);

    if (b->dsa_public_key == NULL ||
        b->dsa_private_key == NULL ||
        b->dsa_signature == NULL) {
        fprintf(
            stderr,
            "ML-DSA allocation failure\n"
        );
        return 0;
    }

    if (run_dsa_keygen(b) != 0) {
        fprintf(
            stderr,
            "ML-DSA setup keygen failed\n"
        );
        return 0;
    }

    if (run_dsa_sign(b) != 0) {
        fprintf(
            stderr,
            "ML-DSA setup signing failed\n"
        );
        return 0;
    }

    if (run_dsa_verify(b) != 0) {
        fprintf(
            stderr,
            "ML-DSA setup verification failed\n"
        );
        return 0;
    }

    return 1;
}

static void cleanup(Bench *b)
{
    free(b->kem_public_key);
    free(b->kem_private_key);
    free(b->kem_ciphertext);
    free(b->kem_shared_secret);

    free(b->dsa_public_key);
    free(b->dsa_private_key);
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
            "usage: wolfssl_bench "
            "{kem-keygen|kem-encaps|kem-decaps|"
            "dsa-keygen|dsa-sign|dsa-verify}\n"
        );
        return 64;
    }

    if (strcmp(argv[1], "kem-keygen") == 0) {
        primitive = "ML-KEM-768";
        fn = run_kem_keygen;
    } else if (
        strcmp(argv[1], "kem-encaps") == 0
    ) {
        primitive = "ML-KEM-768";
        fn = run_kem_encaps;
    } else if (
        strcmp(argv[1], "kem-decaps") == 0
    ) {
        primitive = "ML-KEM-768";
        fn = run_kem_decaps;
    } else if (
        strcmp(argv[1], "dsa-keygen") == 0
    ) {
        primitive = "ML-DSA-65";
        fn = run_dsa_keygen;
    } else if (
        strcmp(argv[1], "dsa-sign") == 0
    ) {
        primitive = "ML-DSA-65";
        fn = run_dsa_sign;
    } else if (
        strcmp(argv[1], "dsa-verify") == 0
    ) {
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
