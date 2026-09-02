#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto/fipsmodule/ml_kem/ml_kem.h"

#include <openssl/evp.h>
#include <openssl/nid.h>

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


typedef struct {
    const char *name;
    int nid;
    size_t public_key_size;
    size_t secret_key_size;
    size_t signature_size;
} MlDsaParams;

static int get_dsa_params(
    const char *name,
    MlDsaParams *params)
{
    if (strcmp(name, "ML-DSA-44") == 0) {
        params->name = name;
        params->nid = NID_MLDSA44;
        params->public_key_size = 1312U;
        params->secret_key_size = 2560U;
        params->signature_size = 2420U;
        return 0;
    }

    if (strcmp(name, "ML-DSA-65") == 0) {
        params->name = name;
        params->nid = NID_MLDSA65;
        params->public_key_size = 1952U;
        params->secret_key_size = 4032U;
        params->signature_size = 3309U;
        return 0;
    }

    if (strcmp(name, "ML-DSA-87") == 0) {
        params->name = name;
        params->nid = NID_MLDSA87;
        params->public_key_size = 2592U;
        params->secret_key_size = 4896U;
        params->signature_size = 4627U;
        return 0;
    }

    fprintf(
        stderr,
        "unsupported ML-DSA parameter set: %s\n",
        name);

    return -1;
}

static int set_signature_context(
    EVP_PKEY_CTX *ctx,
    const uint8_t *context,
    size_t context_len)
{
    if (context_len > 255U) {
        fprintf(stderr, "ML-DSA context exceeds 255 bytes\n");
        return 0;
    }

    return EVP_PKEY_CTX_set1_signature_context_string(
        ctx,
        context_len == 0U ? NULL : context,
        context_len);
}

static int dsa_keygen(
    const MlDsaParams *params,
    const char *xi_hex)
{
    uint8_t *xi = NULL;
    uint8_t *public_key = NULL;
    uint8_t *secret_key = NULL;

    size_t public_key_len = 0;
    size_t secret_key_len = 0;

    EVP_PKEY *pkey = NULL;

    int rc = 1;

    xi = from_hex(xi_hex, 32U);

    if (xi == NULL) {
        fprintf(stderr, "xi must be exactly 32 bytes\n");
        goto cleanup;
    }

    /*
     * AWS-LC's installed public PQDSA API interprets a 32-byte
     * ML-DSA private-key input as the FIPS 204 key-generation seed.
     */
    pkey = EVP_PKEY_pqdsa_new_raw_private_key(
        params->nid,
        xi,
        32U);

    if (pkey == NULL) {
        fprintf(stderr, "AWS-LC seeded ML-DSA keygen failed\n");
        goto cleanup;
    }

    if (!EVP_PKEY_get_raw_public_key(
            pkey,
            NULL,
            &public_key_len) ||
        !EVP_PKEY_get_raw_private_key(
            pkey,
            NULL,
            &secret_key_len)) {
        fprintf(stderr, "AWS-LC ML-DSA key-size query failed\n");
        goto cleanup;
    }

    if (public_key_len != params->public_key_size ||
        secret_key_len != params->secret_key_size) {
        fprintf(
            stderr,
            "AWS-LC returned unexpected ML-DSA key lengths\n");
        goto cleanup;
    }

    public_key = malloc(public_key_len);
    secret_key = malloc(secret_key_len);

    if (public_key == NULL || secret_key == NULL) {
        fprintf(stderr, "allocation failure\n");
        goto cleanup;
    }

    if (!EVP_PKEY_get_raw_public_key(
            pkey,
            public_key,
            &public_key_len) ||
        !EVP_PKEY_get_raw_private_key(
            pkey,
            secret_key,
            &secret_key_len)) {
        fprintf(stderr, "AWS-LC ML-DSA key export failed\n");
        goto cleanup;
    }

    print_hex(
        "public_key",
        public_key,
        public_key_len);

    print_hex(
        "secret_key",
        secret_key,
        secret_key_len);

    rc = 0;

cleanup:
    EVP_PKEY_free(pkey);

    free(xi);
    free(public_key);
    free(secret_key);

    return rc;
}

static int dsa_sign(
    const MlDsaParams *params,
    const char *secret_key_hex,
    const char *message_hex,
    const char *context_hex)
{
    uint8_t *secret_key = NULL;
    uint8_t *message = NULL;
    uint8_t *context = NULL;
    uint8_t *signature = NULL;

    size_t message_len;
    size_t context_len;
    size_t signature_len = 0;

    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *mdctx = NULL;
    EVP_PKEY_CTX *pctx = NULL;

    int rc = 1;

    secret_key = from_hex(
        secret_key_hex,
        params->secret_key_size);

    if (secret_key == NULL) {
        fprintf(stderr, "invalid ML-DSA secret key\n");
        goto cleanup;
    }

    if (message_hex == NULL ||
        (strlen(message_hex) & 1U) != 0U) {
        fprintf(stderr, "invalid message encoding\n");
        goto cleanup;
    }

    message_len = strlen(message_hex) / 2U;
    message = from_hex(message_hex, message_len);

    if (message == NULL) {
        fprintf(stderr, "invalid message\n");
        goto cleanup;
    }

    if (context_hex == NULL ||
        (strlen(context_hex) & 1U) != 0U) {
        fprintf(stderr, "invalid context encoding\n");
        goto cleanup;
    }

    context_len = strlen(context_hex) / 2U;

    if (context_len > 255U) {
        fprintf(stderr, "ML-DSA context exceeds 255 bytes\n");
        goto cleanup;
    }

    context = from_hex(context_hex, context_len);

    if (context == NULL) {
        fprintf(stderr, "invalid context\n");
        goto cleanup;
    }

    pkey = EVP_PKEY_pqdsa_new_raw_private_key(
        params->nid,
        secret_key,
        params->secret_key_size);

    if (pkey == NULL) {
        fprintf(stderr, "AWS-LC ML-DSA private-key import failed\n");
        goto cleanup;
    }

    mdctx = EVP_MD_CTX_new();

    if (mdctx == NULL) {
        fprintf(stderr, "EVP_MD_CTX_new failed\n");
        goto cleanup;
    }

    if (!EVP_DigestSignInit(
            mdctx,
            &pctx,
            NULL,
            NULL,
            pkey)) {
        fprintf(stderr, "EVP_DigestSignInit failed\n");
        goto cleanup;
    }

    if (!set_signature_context(
            pctx,
            context,
            context_len)) {
        fprintf(stderr, "ML-DSA context configuration failed\n");
        goto cleanup;
    }

    if (!EVP_DigestSign(
            mdctx,
            NULL,
            &signature_len,
            message,
            message_len)) {
        fprintf(stderr, "ML-DSA signature-size query failed\n");
        goto cleanup;
    }

    if (signature_len != params->signature_size) {
        fprintf(stderr, "AWS-LC returned unexpected signature size\n");
        goto cleanup;
    }

    signature = malloc(signature_len);

    if (signature == NULL) {
        fprintf(stderr, "allocation failure\n");
        goto cleanup;
    }

    if (!EVP_DigestSign(
            mdctx,
            signature,
            &signature_len,
            message,
            message_len)) {
        fprintf(stderr, "AWS-LC ML-DSA signing failed\n");
        goto cleanup;
    }

    if (signature_len != params->signature_size) {
        fprintf(stderr, "AWS-LC returned unexpected signature length\n");
        goto cleanup;
    }

    print_hex(
        "signature",
        signature,
        signature_len);

    rc = 0;

cleanup:
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);

    free(secret_key);
    free(message);
    free(context);
    free(signature);

    return rc;
}

static int dsa_verify(
    const MlDsaParams *params,
    const char *public_key_hex,
    const char *message_hex,
    const char *context_hex,
    const char *signature_hex)
{
    uint8_t *public_key = NULL;
    uint8_t *message = NULL;
    uint8_t *context = NULL;
    uint8_t *signature = NULL;

    size_t message_len;
    size_t context_len;

    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *mdctx = NULL;
    EVP_PKEY_CTX *pctx = NULL;

    int valid;
    int rc = 1;

    public_key = from_hex(
        public_key_hex,
        params->public_key_size);

    signature = from_hex(
        signature_hex,
        params->signature_size);

    if (public_key == NULL || signature == NULL) {
        /*
         * Structurally malformed keys/signatures are secure rejection,
         * not provider execution failure.
         */
        printf("valid=false\n");
        rc = 0;
        goto cleanup;
    }

    if (message_hex == NULL ||
        (strlen(message_hex) & 1U) != 0U) {
        fprintf(stderr, "invalid message encoding\n");
        goto cleanup;
    }

    message_len = strlen(message_hex) / 2U;
    message = from_hex(message_hex, message_len);

    if (message == NULL) {
        fprintf(stderr, "invalid message\n");
        goto cleanup;
    }

    if (context_hex == NULL ||
        (strlen(context_hex) & 1U) != 0U) {
        fprintf(stderr, "invalid context encoding\n");
        goto cleanup;
    }

    context_len = strlen(context_hex) / 2U;

    if (context_len > 255U) {
        fprintf(stderr, "ML-DSA context exceeds 255 bytes\n");
        goto cleanup;
    }

    context = from_hex(context_hex, context_len);

    if (context == NULL) {
        fprintf(stderr, "invalid context\n");
        goto cleanup;
    }

    pkey = EVP_PKEY_pqdsa_new_raw_public_key(
        params->nid,
        public_key,
        params->public_key_size);

    if (pkey == NULL) {
        printf("valid=false\n");
        rc = 0;
        goto cleanup;
    }

    mdctx = EVP_MD_CTX_new();

    if (mdctx == NULL) {
        fprintf(stderr, "EVP_MD_CTX_new failed\n");
        goto cleanup;
    }

    if (!EVP_DigestVerifyInit(
            mdctx,
            &pctx,
            NULL,
            NULL,
            pkey)) {
        fprintf(stderr, "EVP_DigestVerifyInit failed\n");
        goto cleanup;
    }

    if (!set_signature_context(
            pctx,
            context,
            context_len)) {
        fprintf(stderr, "ML-DSA context configuration failed\n");
        goto cleanup;
    }

    valid = EVP_DigestVerify(
        mdctx,
        signature,
        params->signature_size,
        message,
        message_len);

    printf(
        "valid=%s\n",
        valid == 1 ? "true" : "false");

    rc = 0;

cleanup:
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);

    free(public_key);
    free(message);
    free(context);
    free(signature);

    return rc;
}


int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(
            stderr,
            "usage: awslc_bridge OP PARAMETER_SET [ARGS]\n");
        return 64;
    }

    if (strncmp(argv[1], "kem-", 4U) == 0) {
        MlKemParams params;

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
    }

    if (strncmp(argv[1], "dsa-", 4U) == 0) {
        MlDsaParams params;

        if (get_dsa_params(argv[2], &params) != 0) {
            return 65;
        }

        if (strcmp(argv[1], "dsa-keygen") == 0) {
            if (argc != 4) return 64;

            return dsa_keygen(
                &params,
                argv[3]);
        }

        if (strcmp(argv[1], "dsa-sign") == 0) {
            if (argc != 6) return 64;

            return dsa_sign(
                &params,
                argv[3],
                argv[4],
                argv[5]);
        }

        if (strcmp(argv[1], "dsa-verify") == 0) {
            if (argc != 7) return 64;

            return dsa_verify(
                &params,
                argv[3],
                argv[4],
                argv[5],
                argv[6]);
        }
    }

    fprintf(
        stderr,
        "unsupported operation: %s\n",
        argv[1]);

    return 66;
}
