#define _POSIX_C_SOURCE 200809L

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define SAMPLE_COUNT 100U
#define TARGET_SAMPLE_NS 5000000ULL
#define ALG "ML-DSA-65"

#if defined(CLOCK_MONOTONIC_RAW)
#define BENCH_CLOCK CLOCK_MONOTONIC_RAW
#else
#define BENCH_CLOCK CLOCK_MONOTONIC
#endif

static const unsigned char MESSAGE[] =
    "pqc-rfc9958-rs B1.3.5 performance baseline";
static const unsigned char CONTEXT[] = "benchmark";

typedef struct {
    unsigned char seed[32];
    unsigned char randomness[32];

    unsigned char *public_key;
    size_t public_key_len;

    unsigned char *private_key;
    size_t private_key_len;

    unsigned char *signature;
    size_t signature_len;

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

    return (uint64_t)ts.tv_sec * 1000000000ULL +
           (uint64_t)ts.tv_nsec;
}

static EVP_PKEY *import_key(
    unsigned char *pub,
    size_t pub_len,
    unsigned char *priv,
    size_t priv_len)
{
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *key = NULL;
    OSSL_PARAM params[3];
    size_t i = 0;
    int selection;

    ctx = EVP_PKEY_CTX_new_from_name(NULL, ALG, NULL);
    if (ctx == NULL) {
        return NULL;
    }

    if (EVP_PKEY_fromdata_init(ctx) <= 0) {
        goto done;
    }

    if (pub != NULL) {
        params[i++] = OSSL_PARAM_construct_octet_string(
            OSSL_PKEY_PARAM_PUB_KEY,
            pub,
            pub_len);
    }

    if (priv != NULL) {
        params[i++] = OSSL_PARAM_construct_octet_string(
            OSSL_PKEY_PARAM_PRIV_KEY,
            priv,
            priv_len);
    }

    params[i] = OSSL_PARAM_construct_end();

    if (pub != NULL && priv != NULL) {
        selection = EVP_PKEY_KEYPAIR;
    } else if (priv != NULL) {
        selection = EVP_PKEY_PRIVATE_KEY;
    } else {
        selection = EVP_PKEY_PUBLIC_KEY;
    }

    if (EVP_PKEY_fromdata(
            ctx,
            &key,
            selection,
            params) <= 0) {
        key = NULL;
    }

done:
    EVP_PKEY_CTX_free(ctx);
    return key;
}

static int export_component(
    EVP_PKEY *key,
    const char *name,
    unsigned char **buf,
    size_t *len)
{
    *buf = NULL;
    *len = 0;

    if (EVP_PKEY_get_octet_string_param(
            key,
            name,
            NULL,
            0,
            len) <= 0) {
        return 0;
    }

    *buf = malloc(*len);
    if (*buf == NULL) {
        return 0;
    }

    if (EVP_PKEY_get_octet_string_param(
            key,
            name,
            *buf,
            *len,
            len) <= 0) {
        free(*buf);
        *buf = NULL;
        return 0;
    }

    return 1;
}

static int generate_keypair(
    Bench *b,
    unsigned char **pub,
    size_t *pub_len,
    unsigned char **priv,
    size_t *priv_len)
{
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *key = NULL;
    OSSL_PARAM params[2];
    int ok = 0;

    ctx = EVP_PKEY_CTX_new_from_name(NULL, ALG, NULL);
    if (ctx == NULL) goto done;

    if (EVP_PKEY_keygen_init(ctx) <= 0) goto done;

    params[0] = OSSL_PARAM_construct_octet_string(
        OSSL_PKEY_PARAM_ML_DSA_SEED,
        b->seed,
        sizeof(b->seed));
    params[1] = OSSL_PARAM_construct_end();

    if (EVP_PKEY_CTX_set_params(ctx, params) <= 0) {
        goto done;
    }

    if (EVP_PKEY_generate(ctx, &key) <= 0) {
        goto done;
    }

    if (!export_component(
            key,
            OSSL_PKEY_PARAM_PUB_KEY,
            pub,
            pub_len)) {
        goto done;
    }

    if (!export_component(
            key,
            OSSL_PKEY_PARAM_PRIV_KEY,
            priv,
            priv_len)) {
        free(*pub);
        *pub = NULL;
        goto done;
    }

    ok = 1;

done:
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(ctx);
    return ok;
}

static int run_keygen(Bench *b)
{
    unsigned char *pub = NULL;
    unsigned char *priv = NULL;
    size_t pub_len = 0;
    size_t priv_len = 0;

    int ok = generate_keypair(
        b,
        &pub,
        &pub_len,
        &priv,
        &priv_len);

    if (ok) {
        b->sink ^= pub[0];
        b->sink ^= priv[0];
    }

    free(pub);
    free(priv);
    return ok;
}

static int sign_once(
    Bench *b,
    unsigned char **out_sig,
    size_t *out_sig_len)
{
    EVP_PKEY *key = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_SIGNATURE *signature_alg = NULL;
    OSSL_PARAM params[3];
    unsigned char *sig = NULL;
    size_t sig_len = 0;
    int ok = 0;

    key = import_key(
        NULL,
        0,
        b->private_key,
        b->private_key_len);
    if (key == NULL) goto done;

    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL);
    if (ctx == NULL) goto done;

    signature_alg = EVP_SIGNATURE_fetch(NULL, ALG, NULL);
    if (signature_alg == NULL) goto done;

    params[0] = OSSL_PARAM_construct_octet_string(
        OSSL_SIGNATURE_PARAM_CONTEXT_STRING,
        (void *)CONTEXT,
        sizeof(CONTEXT) - 1U);

    params[1] = OSSL_PARAM_construct_octet_string(
        OSSL_SIGNATURE_PARAM_TEST_ENTROPY,
        b->randomness,
        sizeof(b->randomness));

    params[2] = OSSL_PARAM_construct_end();

    if (EVP_PKEY_sign_message_init(
            ctx,
            signature_alg,
            params) <= 0) {
        goto done;
    }

    if (EVP_PKEY_sign(
            ctx,
            NULL,
            &sig_len,
            MESSAGE,
            sizeof(MESSAGE) - 1U) <= 0) {
        goto done;
    }

    sig = malloc(sig_len);
    if (sig == NULL) goto done;

    if (EVP_PKEY_sign(
            ctx,
            sig,
            &sig_len,
            MESSAGE,
            sizeof(MESSAGE) - 1U) <= 0) {
        goto done;
    }

    *out_sig = sig;
    *out_sig_len = sig_len;
    sig = NULL;
    ok = 1;

done:
    free(sig);
    EVP_SIGNATURE_free(signature_alg);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(key);
    return ok;
}

static int run_sign(Bench *b)
{
    unsigned char *sig = NULL;
    size_t sig_len = 0;

    int ok = sign_once(b, &sig, &sig_len);

    if (ok) {
        b->sink ^= sig[0];
    }

    free(sig);
    return ok;
}

static int run_verify(Bench *b)
{
    EVP_PKEY *key = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_SIGNATURE *signature_alg = NULL;
    OSSL_PARAM params[2];
    int valid = -1;
    int ok = 0;

    key = import_key(
        b->public_key,
        b->public_key_len,
        NULL,
        0);
    if (key == NULL) goto done;

    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL);
    if (ctx == NULL) goto done;

    signature_alg = EVP_SIGNATURE_fetch(NULL, ALG, NULL);
    if (signature_alg == NULL) goto done;

    params[0] = OSSL_PARAM_construct_octet_string(
        OSSL_SIGNATURE_PARAM_CONTEXT_STRING,
        (void *)CONTEXT,
        sizeof(CONTEXT) - 1U);

    params[1] = OSSL_PARAM_construct_end();

    if (EVP_PKEY_verify_message_init(
            ctx,
            signature_alg,
            params) <= 0) {
        goto done;
    }

    valid = EVP_PKEY_verify(
        ctx,
        b->signature,
        b->signature_len,
        MESSAGE,
        sizeof(MESSAGE) - 1U);

    if (valid != 1) {
        goto done;
    }

    b->sink ^= 1U;
    ok = 1;

done:
    EVP_SIGNATURE_free(signature_alg);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(key);
    return ok;
}

static uint64_t measure_iterations(
    Bench *b,
    bench_fn fn,
    uint64_t iterations)
{
    uint64_t start = now_ns();

    for (uint64_t i = 0; i < iterations; ++i) {
        if (!fn(b)) {
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
        if (!fn(b)) {
            fprintf(stderr, "warm-up operation failed\n");
            exit(5);
        }
    }
}

static void run_benchmark(
    const char *operation,
    Bench *b,
    bench_fn fn)
{
    uint64_t iterations;

    warm_up(b, fn);
    iterations = calibrate(b, fn);

    printf("{\n");
    printf("  \"provider\": \"openssl\",\n");
    printf("  \"primitive\": \"ML-DSA-65\",\n");
    printf("  \"operation\": \"%s\",\n", operation);
    printf("  \"samples\": %u,\n", SAMPLE_COUNT);
    printf(
        "  \"iterations_per_sample\": %llu,\n",
        (unsigned long long)iterations);
    printf("  \"sample_ns\": [\n");

    for (unsigned int sample = 0;
         sample < SAMPLE_COUNT;
         ++sample) {
        uint64_t elapsed =
            measure_iterations(b, fn, iterations);

        double ns =
            (double)elapsed / (double)iterations;

        printf(
            "    %.6f%s\n",
            ns,
            sample + 1U == SAMPLE_COUNT ? "" : ",");
    }

    printf("  ],\n");
    printf("  \"sink\": %u\n", (unsigned int)b->sink);
    printf("}\n");
}

static int prepare(Bench *b)
{
    memset(b, 0, sizeof(*b));

    memset(b->seed, 0x65, sizeof(b->seed));
    memset(b->randomness, 0x00, sizeof(b->randomness));

    if (!generate_keypair(
            b,
            &b->public_key,
            &b->public_key_len,
            &b->private_key,
            &b->private_key_len)) {
        fprintf(stderr, "setup key generation failed\n");
        return 0;
    }

    if (!sign_once(
            b,
            &b->signature,
            &b->signature_len)) {
        fprintf(stderr, "setup signing failed\n");
        return 0;
    }

    if (!run_verify(b)) {
        fprintf(stderr, "setup verification failed\n");
        return 0;
    }

    return 1;
}

static void cleanup(Bench *b)
{
    free(b->public_key);
    free(b->private_key);
    free(b->signature);
}

int main(int argc, char **argv)
{
    Bench bench;
    bench_fn fn = NULL;

    if (argc != 2) {
        fprintf(
            stderr,
            "usage: openssl_dsa_bench "
            "{dsa-keygen|dsa-sign|dsa-verify}\n");
        return 64;
    }

    if (strcmp(argv[1], "dsa-keygen") == 0) {
        fn = run_keygen;
    } else if (strcmp(argv[1], "dsa-sign") == 0) {
        fn = run_sign;
    } else if (strcmp(argv[1], "dsa-verify") == 0) {
        fn = run_verify;
    } else {
        fprintf(stderr, "unsupported operation: %s\n", argv[1]);
        return 65;
    }

    if (!prepare(&bench)) {
        cleanup(&bench);
        return 1;
    }

    run_benchmark(argv[1], &bench, fn);
    cleanup(&bench);

    return 0;
}
