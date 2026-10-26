// SPDX-License-Identifier: MIT
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "params.h"
#include "poly.h"

static int16_t coefficient(int pattern, int role, int i, int j, int k) {
    if (pattern == 0) return 0;
    if (pattern == 1) {
        if (k != 0 && k != 255) return 0;
        return (int16_t)(role == 0 ? (i * 3 + j + 1)
                       : role == 1 ? (i + 2)
                       : (i * 7 + k % 5 + 11));
    }
    int x = (i * 29 + j * 17 + k * 7 + role * 13) % 31;
    return (int16_t)(x - 15);
}

static void fill_poly(poly *p, int pattern, int role,
                      int i, int j, int shift) {
    for (int k = 0; k < SMAUGT_N; k++) {
        int16_t v = coefficient(pattern, role, i, j, k);
        if (role == 0) {
            p->coeffs[k] = (int16_t)((uint16_t)v << shift);
        } else {
            p->coeffs[k] = v;
        }
    }
}

static void print_poly(const poly *p, int *first) {
    for (int k = 0; k < SMAUGT_N; k++) {
        if (!*first) putchar(',');
        printf("%u", (unsigned)(uint16_t)p->coeffs[k]);
        *first = 0;
    }
}

int main(int argc, char **argv) {
    if (argc != 4) return 2;

    int op = atoi(argv[1]);
    int pattern = atoi(argv[2]);
    int shift = atoi(argv[3]);

    if (op < 0 || op > 2 || pattern < 0 || pattern > 2 ||
        shift < 0 || shift >= 16) return 2;

    polyvec secret;
    polyvec vector;
    polyvec matrix[SMAUGT_K];
    polyvec output;
    poly result;

    memset(&secret, 0, sizeof(secret));
    memset(&vector, 0, sizeof(vector));
    memset(&matrix, 0, sizeof(matrix));
    memset(&output, 0, sizeof(output));
    memset(&result, 0, sizeof(result));

    for (int i = 0; i < SMAUGT_K; i++) {
        fill_poly(&secret.vec[i], pattern, 1, i, 0, 0);
        fill_poly(&vector.vec[i], pattern, 0, 0, i, shift);
        for (int j = 0; j < SMAUGT_K; j++) {
            fill_poly(&matrix[i].vec[j], pattern, 0,
                      i, j, SMAUGT_MODULUS_16_LOG_Q);
        }
    }

    int first = 1;
    if (op == 0) {
        fill_poly(&result, pattern, 2, 0, 0, 0);
        vec_vec_mult_add(&result, &vector, &secret, (uint8_t)shift);
        print_poly(&result, &first);
    } else {
        if (op == 2) {
            for (int i = 0; i < SMAUGT_K; i++) {
                fill_poly(&output.vec[i], pattern, 2, i, 0, 0);
            }
        }
        if (op == 1) {
            matrix_vec_mult_add(&output, matrix, &secret);
        } else {
            matrix_vec_mult_sub(&output, matrix, &secret);
        }
        for (int i = 0; i < SMAUGT_K; i++) {
            print_poly(&output.vec[i], &first);
        }
    }
    putchar('\n');
    return 0;
}
