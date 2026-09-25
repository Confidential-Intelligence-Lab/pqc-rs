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
#define ALG "ML-KEM-768"

#if defined(CLOCK_MONOTONIC_RAW)
#define BENCH_CLOCK CLOCK_MONOTONIC_RAW
#else
#define BENCH_CLOCK CLOCK_MONOTONIC
#endif

typedef struct {
    unsigned char seed[64];
    unsigned char encaps_seed[32];

    unsigned char *public_key;
    size_t public_key_len;

    unsigned char *private_key;
    size_t private_key_len;

    unsigned char *ciphertext;
    size_t ciphertext_len;

    unsigned char *shared_secret;
    size_t shared_secret_len;

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
    const char *alg,
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

    ctx = EVP_PKEY_CTX_new_from_name(NULL, alg, NULL);
    if (ctx == NULL) {
        return NULL;
    }

    if (EVP_PKEY_fromdata_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
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

    EVP_PKEY_CTX_free(ctx);
    return key;
}

static int export_component(
    EVP_PKEY *key,
    const char *name,
    unsigned char **buf,
    size_t *len)
{
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
        OSSL_PKEY_PARAM_ML_KEM_SEED,
        b->seed,
        sizeof(b->seed));
    params[1] = OSSL_PARAM_construct_end();

    if (EVP_PKEY_CTX_set_params(ctx, params) <= 0) goto done;
    if (EVP_PKEY_generate(ctx, &key) <= 0) goto done;

    if (!export_component(
            key,
            OSSL_PKEY_PARAM_PUB_KEY,
            pub,
            pub_len)) goto done;

    if (!export_component(
            key,
            OSSL_PKEY_PARAM_PRIV_KEY,
            priv,
            priv_len)) goto done;

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

static int run_encaps(Bench *b)
{
    EVP_PKEY *key = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    OSSL_PARAM params[2];

    unsigned char *ct = NULL;
    unsigned char *ss = NULL;
    size_t ct_len = 0;
    size_t ss_len = 0;

    int ok = 0;

    key = import_key(
        ALG,
        b->public_key,
        b->public_key_len,
        NULL,
        0);
    if (key == NULL) goto done;

    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL);
    if (ctx == NULL) goto done;

    params[0] = OSSL_PARAM_construct_octet_string(
        OSSL_KEM_PARAM_IKME,
        b->encaps_seed,
        sizeof(b->encaps_seed));
    params[1] = OSSL_PARAM_construct_end();

    if (EVP_PKEY_encapsulate_init(ctx, params) <= 0) goto done;

    if (EVP_PKEY_encapsulate(
            ctx,
            NULL,
            &ct_len,
            NULL,
            &ss_len) <= 0) goto done;

    ct = malloc(ct_len);
    ss = malloc(ss_len);
    if (ct == NULL || ss == NULL) goto done;

    if (EVP_PKEY_encapsulate(
            ctx,
            ct,
            &ct_len,
            ss,
            &ss_len) <= 0) goto done;

    b->sink ^= ct[0];
    b->sink ^= ss[0];
    ok = 1;

done:
    free(ct);
    free(ss);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(key);
    return ok;
}

static int run_decaps(Bench *b)
{
    EVP_PKEY *key = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    unsigned char *ss = NULL;
    size_t ss_len = 0;
    int ok = 0;

    key = import_key(
        ALG,
        NULL,
        0,
        b->private_key,
        b->private_key_len);
    if (key == NULL) goto done;

    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL);
    if (ctx == NULL) goto done;

    if (EVP_PKEY_decapsulate_init(ctx, NULL) <= 0) goto done;

    if (EVP_PKEY_decapsulate(
            ctx,
            NULL,
            &ss_len,
            b->ciphertext,
            b->ciphertext_len) <= 0) goto done;

    ss = malloc(ss_len);
    if (ss == NULL) goto done;

    if (EVP_PKEY_decapsulate(
            ctx,
            ss,
            &ss_len,
            b->ciphertext,
            b->ciphertext_len) <= 0) goto done;

    b->sink ^= ss[0];
    ok = 1;

done:
    free(ss);
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

static uint64_t calibrate(Bench *b, bench_fn fn)
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

static void warm_up(Bench *b, bench_fn fn)
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
    warm_up(b, fn);

    uint64_t iterations = calibrate(b, fn);

    printf("{\n");
    printf("  \"provider\": \"openssl\",\n");
    printf("  \"primitive\": \"ML-KEM-768\",\n");
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

    memset(b->seed, 0x33, 32);
    memset(b->seed + 32, 0x44, 32);
    memset(b->encaps_seed, 0x77, 32);

    if (!generate_keypair(
            b,
            &b->public_key,
            &b->public_key_len,
            &b->private_key,
            &b->private_key_len)) {
        fprintf(stderr, "setup key generation failed\n");
        return 0;
    }

    EVP_PKEY *key = import_key(
        ALG,
        b->public_key,
        b->public_key_len,
        NULL,
        0);
    if (key == NULL) {
        fprintf(stderr, "setup public-key import failed\n");
        return 0;
    }

    EVP_PKEY_CTX *ctx =
        EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL);
    if (ctx == NULL) {
        EVP_PKEY_free(key);
        return 0;
    }

    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_octet_string(
        OSSL_KEM_PARAM_IKME,
        b->encaps_seed,
        sizeof(b->encaps_seed));
    params[1] = OSSL_PARAM_construct_end();

    if (EVP_PKEY_encapsulate_init(ctx, params) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(key);
        return 0;
    }

    if (EVP_PKEY_encapsulate(
            ctx,
            NULL,
            &b->ciphertext_len,
            NULL,
            &b->shared_secret_len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(key);
        return 0;
    }

    b->ciphertext = malloc(b->ciphertext_len);
    b->shared_secret = malloc(b->shared_secret_len);

    if (b->ciphertext == NULL ||
        b->shared_secret == NULL) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(key);
        return 0;
    }

    if (EVP_PKEY_encapsulate(
            ctx,
            b->ciphertext,
            &b->ciphertext_len,
            b->shared_secret,
            &b->shared_secret_len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(key);
        return 0;
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(key);

    return 1;
}

static void cleanup(Bench *b)
{
    free(b->public_key);
    free(b->private_key);
    free(b->ciphertext);
    free(b->shared_secret);
}

int main(int argc, char **argv)
{
    Bench bench;
    bench_fn fn = NULL;

    if (argc != 2) {
        fprintf(
            stderr,
            "usage: openssl_bench "
            "{kem-keygen|kem-encaps|kem-decaps}\n");
        return 64;
    }

    if (strcmp(argv[1], "kem-keygen") == 0) {
        fn = run_keygen;
    } else if (strcmp(argv[1], "kem-encaps") == 0) {
        fn = run_encaps;
    } else if (strcmp(argv[1], "kem-decaps") == 0) {
        fn = run_decaps;
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
