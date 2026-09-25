#define _POSIX_C_SOURCE 200809L

#include <oqs/oqs.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define SAMPLE_COUNT 100U
#define TARGET_SAMPLE_NS 5000000ULL

#if defined(CLOCK_MONOTONIC_RAW)
#define BENCH_CLOCK CLOCK_MONOTONIC_RAW
#else
#define BENCH_CLOCK CLOCK_MONOTONIC
#endif

typedef struct {
    OQS_KEM *kem;

    uint8_t *public_key;
    uint8_t *secret_key;
    uint8_t *ciphertext;
    uint8_t *shared_secret;

    uint8_t keygen_seed[64];
    uint8_t encaps_seed[32];

    volatile uint8_t sink;
} KemBench;

typedef OQS_STATUS (*bench_fn)(KemBench *);

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

static OQS_STATUS run_keygen(KemBench *b)
{
    OQS_STATUS status = OQS_KEM_keypair_derand(
        b->kem,
        b->public_key,
        b->secret_key,
        b->keygen_seed);

    if (status == OQS_SUCCESS) {
        b->sink ^= b->public_key[0];
        b->sink ^= b->secret_key[0];
    }

    return status;
}

static OQS_STATUS run_encaps(KemBench *b)
{
    OQS_STATUS status = OQS_KEM_encaps_derand(
        b->kem,
        b->ciphertext,
        b->shared_secret,
        b->public_key,
        b->encaps_seed);

    if (status == OQS_SUCCESS) {
        b->sink ^= b->ciphertext[0];
        b->sink ^= b->shared_secret[0];
    }

    return status;
}

static OQS_STATUS run_decaps(KemBench *b)
{
    OQS_STATUS status = OQS_KEM_decaps(
        b->kem,
        b->shared_secret,
        b->ciphertext,
        b->secret_key);

    if (status == OQS_SUCCESS) {
        b->sink ^= b->shared_secret[0];
    }

    return status;
}

static uint64_t measure_iterations(
    KemBench *b,
    bench_fn fn,
    uint64_t iterations)
{
    uint64_t start;
    uint64_t end;

    start = now_ns();

    for (uint64_t i = 0; i < iterations; ++i) {
        if (fn(b) != OQS_SUCCESS) {
            fprintf(stderr, "cryptographic operation failed\n");
            exit(3);
        }
    }

    end = now_ns();

    return end - start;
}

static uint64_t calibrate(KemBench *b, bench_fn fn)
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

static void warm_up(KemBench *b, bench_fn fn)
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
    KemBench *b,
    bench_fn fn)
{
    uint64_t iterations;

    warm_up(b, fn);
    iterations = calibrate(b, fn);

    printf("{\n");
    printf("  \"provider\": \"liboqs\",\n");
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

        double per_operation_ns =
            (double)elapsed / (double)iterations;

        printf(
            "    %.6f%s\n",
            per_operation_ns,
            sample + 1U == SAMPLE_COUNT ? "" : ",");
    }

    printf("  ],\n");
    printf("  \"sink\": %u\n", (unsigned int)b->sink);
    printf("}\n");
}

static int init_bench(KemBench *b)
{
    memset(b, 0, sizeof(*b));

    b->kem = OQS_KEM_new("ML-KEM-768");
    if (b->kem == NULL) {
        fprintf(stderr, "ML-KEM-768 unavailable in liboqs\n");
        return 1;
    }

    b->public_key =
        malloc(b->kem->length_public_key);
    b->secret_key =
        malloc(b->kem->length_secret_key);
    b->ciphertext =
        malloc(b->kem->length_ciphertext);
    b->shared_secret =
        malloc(b->kem->length_shared_secret);

    if (b->public_key == NULL ||
        b->secret_key == NULL ||
        b->ciphertext == NULL ||
        b->shared_secret == NULL) {
        fprintf(stderr, "allocation failure\n");
        return 1;
    }

    memset(b->keygen_seed, 0x33, 32);
    memset(b->keygen_seed + 32, 0x44, 32);
    memset(b->encaps_seed, 0x77, 32);

    if (OQS_KEM_keypair_derand(
            b->kem,
            b->public_key,
            b->secret_key,
            b->keygen_seed) != OQS_SUCCESS) {
        fprintf(stderr, "setup key generation failed\n");
        return 1;
    }

    if (OQS_KEM_encaps_derand(
            b->kem,
            b->ciphertext,
            b->shared_secret,
            b->public_key,
            b->encaps_seed) != OQS_SUCCESS) {
        fprintf(stderr, "setup encapsulation failed\n");
        return 1;
    }

    return 0;
}

static void free_bench(KemBench *b)
{
    if (b == NULL) {
        return;
    }

    free(b->public_key);
    free(b->secret_key);
    free(b->ciphertext);
    free(b->shared_secret);
    OQS_KEM_free(b->kem);
}

int main(int argc, char **argv)
{
    KemBench bench;
    bench_fn fn = NULL;

    if (argc != 2) {
        fprintf(
            stderr,
            "usage: liboqs_bench "
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

    if (init_bench(&bench) != 0) {
        free_bench(&bench);
        return 1;
    }

    run_benchmark(argv[1], &bench, fn);
    free_bench(&bench);

    return 0;
}
