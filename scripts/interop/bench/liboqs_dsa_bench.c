#define _POSIX_C_SOURCE 200809L

#include <oqs/oqs.h>

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
    OQS_SIG *sig;

    unsigned char *public_key;
    unsigned char *secret_key;
    unsigned char *signature;
    size_t signature_len;

    volatile unsigned char sink;
} DsaBench;

typedef OQS_STATUS (*bench_fn)(DsaBench *);

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

static OQS_STATUS run_keygen(DsaBench *b)
{
    OQS_STATUS status =
        OQS_SIG_keypair(
            b->sig,
            b->public_key,
            b->secret_key);

    if (status == OQS_SUCCESS) {
        b->sink ^= b->public_key[0];
        b->sink ^= b->secret_key[0];
    }

    return status;
}

static OQS_STATUS run_sign(DsaBench *b)
{
    size_t signature_len = 0;

    OQS_STATUS status =
        OQS_SIG_sign_with_ctx_str(
            b->sig,
            b->signature,
            &signature_len,
            MESSAGE,
            sizeof(MESSAGE) - 1U,
            CONTEXT,
            sizeof(CONTEXT) - 1U,
            b->secret_key);

    if (status == OQS_SUCCESS) {
        b->signature_len = signature_len;
        b->sink ^= b->signature[0];
    }

    return status;
}

static OQS_STATUS run_verify(DsaBench *b)
{
    OQS_STATUS status =
        OQS_SIG_verify_with_ctx_str(
            b->sig,
            MESSAGE,
            sizeof(MESSAGE) - 1U,
            b->signature,
            b->signature_len,
            CONTEXT,
            sizeof(CONTEXT) - 1U,
            b->public_key);

    b->sink ^= (unsigned char)(status == OQS_SUCCESS);

    return status;
}

static uint64_t measure_iterations(
    DsaBench *b,
    bench_fn fn,
    uint64_t iterations)
{
    uint64_t start = now_ns();

    for (uint64_t i = 0; i < iterations; ++i) {
        if (fn(b) != OQS_SUCCESS) {
            fprintf(stderr, "cryptographic operation failed\n");
            exit(3);
        }
    }

    return now_ns() - start;
}

static uint64_t calibrate(
    DsaBench *b,
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
    DsaBench *b,
    bench_fn fn)
{
    uint64_t start = now_ns();

    while (now_ns() - start < 3000000000ULL) {
        if (fn(b) != OQS_SUCCESS) {
            fprintf(stderr, "warm-up operation failed\n");
            exit(5);
        }
    }
}

static void run_benchmark(
    const char *operation,
    DsaBench *b,
    bench_fn fn)
{
    warm_up(b, fn);

    uint64_t iterations = calibrate(b, fn);

    printf("{\n");
    printf("  \"provider\": \"liboqs\",\n");
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

static int init_bench(DsaBench *b)
{
    memset(b, 0, sizeof(*b));

    b->sig = OQS_SIG_new(ALG);
    if (b->sig == NULL) {
        fprintf(stderr, "%s unavailable in liboqs\n", ALG);
        return 1;
    }

    b->public_key =
        malloc(b->sig->length_public_key);
    b->secret_key =
        malloc(b->sig->length_secret_key);
    b->signature =
        malloc(b->sig->length_signature);

    if (b->public_key == NULL ||
        b->secret_key == NULL ||
        b->signature == NULL) {
        fprintf(stderr, "allocation failure\n");
        return 1;
    }

    if (OQS_SIG_keypair(
            b->sig,
            b->public_key,
            b->secret_key) != OQS_SUCCESS) {
        fprintf(stderr, "setup key generation failed\n");
        return 1;
    }

    b->signature_len = 0;

    if (OQS_SIG_sign_with_ctx_str(
            b->sig,
            b->signature,
            &b->signature_len,
            MESSAGE,
            sizeof(MESSAGE) - 1U,
            CONTEXT,
            sizeof(CONTEXT) - 1U,
            b->secret_key) != OQS_SUCCESS) {
        fprintf(stderr, "setup signing failed\n");
        return 1;
    }

    if (OQS_SIG_verify_with_ctx_str(
            b->sig,
            MESSAGE,
            sizeof(MESSAGE) - 1U,
            b->signature,
            b->signature_len,
            CONTEXT,
            sizeof(CONTEXT) - 1U,
            b->public_key) != OQS_SUCCESS) {
        fprintf(stderr, "setup verification failed\n");
        return 1;
    }

    return 0;
}

static void free_bench(DsaBench *b)
{
    free(b->public_key);
    free(b->secret_key);
    free(b->signature);
    OQS_SIG_free(b->sig);
}

int main(int argc, char **argv)
{
    DsaBench bench;
    bench_fn fn = NULL;

    if (argc != 2) {
        fprintf(
            stderr,
            "usage: liboqs_dsa_bench "
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

    if (init_bench(&bench) != 0) {
        free_bench(&bench);
        return 1;
    }

    run_benchmark(argv[1], &bench, fn);
    free_bench(&bench);

    return 0;
}
