#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/wc_mlkem.h>
#include <wolfssl/wolfcrypt/wc_mldsa.h>

typedef struct {
    int type;
    const char *name;
} MlKemParams;

static int get_params(
    const char *name,
    MlKemParams *params
)
{
    if (strcmp(name, "ML-KEM-512") == 0) {
        params->type = WC_ML_KEM_512;
        params->name = "ML-KEM-512";
        return 0;
    }

    if (strcmp(name, "ML-KEM-768") == 0) {
        params->type = WC_ML_KEM_768;
        params->name = "ML-KEM-768";
        return 0;
    }

    if (strcmp(name, "ML-KEM-1024") == 0) {
        params->type = WC_ML_KEM_1024;
        params->name = "ML-KEM-1024";
        return 0;
    }

    fprintf(
        stderr,
        "unsupported parameter set: %s\n",
        name
    );

    return -1;
}

static unsigned char *from_hex(
    const char *hex,
    size_t expected_len
)
{
    unsigned char *out;
    size_t i;

    if (hex == NULL) {
        return NULL;
    }

    if (strlen(hex) != expected_len * 2U) {
        return NULL;
    }

    out = (unsigned char *)malloc(
        expected_len == 0U ? 1U : expected_len
    );

    if (out == NULL) {
        return NULL;
    }

    for (i = 0; i < expected_len; i++) {
        unsigned int value;

        if (sscanf(
                hex + (2U * i),
                "%2x",
                &value
            ) != 1) {
            free(out);
            return NULL;
        }

        out[i] = (unsigned char)value;
    }

    return out;
}

static void print_hex(
    const char *name,
    const unsigned char *data,
    size_t len
)
{
    size_t i;

    printf("%s=", name);

    for (i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }

    printf("\n");
}

static int init_key(
    MlKemKey *key,
    int type
)
{
    int rc = wc_MlKemKey_Init(
        key,
        type,
        NULL,
        INVALID_DEVID
    );

    if (rc != 0) {
        fprintf(
            stderr,
            "wc_MlKemKey_Init failed: %d\n",
            rc
        );
    }

    return rc;
}

static int query_sizes(
    MlKemKey *key,
    word32 *public_key_size,
    word32 *private_key_size,
    word32 *ciphertext_size,
    word32 *shared_secret_size
)
{
    int rc;

    rc = wc_MlKemKey_PublicKeySize(
        key,
        public_key_size
    );
    if (rc != 0) return rc;

    rc = wc_MlKemKey_PrivateKeySize(
        key,
        private_key_size
    );
    if (rc != 0) return rc;

    rc = wc_MlKemKey_CipherTextSize(
        key,
        ciphertext_size
    );
    if (rc != 0) return rc;

    return wc_MlKemKey_SharedSecretSize(
        key,
        shared_secret_size
    );
}

static int kem_keygen(
    const MlKemParams *params,
    const char *d_hex,
    const char *z_hex
)
{
    MlKemKey key;

    unsigned char *d = NULL;
    unsigned char *z = NULL;
    unsigned char *public_key = NULL;
    unsigned char *private_key = NULL;

    unsigned char randomness[
        WC_ML_KEM_MAKEKEY_RAND_SZ
    ];

    word32 public_key_size = 0;
    word32 private_key_size = 0;
    word32 ciphertext_size = 0;
    word32 shared_secret_size = 0;

    int initialized = 0;
    int rc = 1;

    d = from_hex(d_hex, WC_ML_KEM_SYM_SZ);
    z = from_hex(z_hex, WC_ML_KEM_SYM_SZ);

    if (d == NULL || z == NULL) {
        fprintf(
            stderr,
            "d and z must each be 32 bytes\n"
        );
        goto cleanup;
    }

    memcpy(
        randomness,
        d,
        WC_ML_KEM_SYM_SZ
    );

    memcpy(
        randomness + WC_ML_KEM_SYM_SZ,
        z,
        WC_ML_KEM_SYM_SZ
    );

    rc = init_key(&key, params->type);
    if (rc != 0) goto cleanup;

    initialized = 1;

    rc = query_sizes(
        &key,
        &public_key_size,
        &private_key_size,
        &ciphertext_size,
        &shared_secret_size
    );

    if (rc != 0) {
        fprintf(stderr, "size query failed: %d\n", rc);
        goto cleanup;
    }

    public_key = (unsigned char *)malloc(
        public_key_size
    );

    private_key = (unsigned char *)malloc(
        private_key_size
    );

    if (public_key == NULL || private_key == NULL) {
        fprintf(stderr, "allocation failure\n");
        rc = 1;
        goto cleanup;
    }

    rc = wc_MlKemKey_MakeKeyWithRandom(
        &key,
        randomness,
        (int)sizeof(randomness)
    );

    if (rc != 0) {
        fprintf(
            stderr,
            "wc_MlKemKey_MakeKeyWithRandom failed: %d\n",
            rc
        );
        goto cleanup;
    }

    rc = wc_MlKemKey_EncodePublicKey(
        &key,
        public_key,
        public_key_size
    );

    if (rc != 0) goto cleanup;

    rc = wc_MlKemKey_EncodePrivateKey(
        &key,
        private_key,
        private_key_size
    );

    if (rc != 0) goto cleanup;

    print_hex(
        "public_key",
        public_key,
        public_key_size
    );

    print_hex(
        "secret_key",
        private_key,
        private_key_size
    );

    rc = 0;

cleanup:

    if (initialized) {
        (void)wc_MlKemKey_Free(&key);
    }

    free(d);
    free(z);
    free(public_key);
    free(private_key);

    return rc;
}

static int kem_encaps(
    const MlKemParams *params,
    const char *public_key_hex,
    const char *m_hex
)
{
    MlKemKey key;

    unsigned char *public_key = NULL;
    unsigned char *m = NULL;
    unsigned char *ciphertext = NULL;
    unsigned char *shared_secret = NULL;

    word32 public_key_size = 0;
    word32 private_key_size = 0;
    word32 ciphertext_size = 0;
    word32 shared_secret_size = 0;

    int initialized = 0;
    int rc = 1;

    rc = init_key(&key, params->type);
    if (rc != 0) goto cleanup;

    initialized = 1;

    rc = query_sizes(
        &key,
        &public_key_size,
        &private_key_size,
        &ciphertext_size,
        &shared_secret_size
    );

    if (rc != 0) goto cleanup;

    public_key = from_hex(
        public_key_hex,
        public_key_size
    );

    m = from_hex(
        m_hex,
        WC_ML_KEM_ENC_RAND_SZ
    );

    if (public_key == NULL || m == NULL) {
        fprintf(stderr, "invalid encapsulation input\n");
        rc = 1;
        goto cleanup;
    }

    ciphertext = (unsigned char *)malloc(
        ciphertext_size
    );

    shared_secret = (unsigned char *)malloc(
        shared_secret_size
    );

    if (
        ciphertext == NULL ||
        shared_secret == NULL
    ) {
        fprintf(stderr, "allocation failure\n");
        rc = 1;
        goto cleanup;
    }

    rc = wc_MlKemKey_DecodePublicKey(
        &key,
        public_key,
        public_key_size
    );

    if (rc != 0) {
        fprintf(
            stderr,
            "DecodePublicKey failed: %d\n",
            rc
        );
        goto cleanup;
    }

    rc = wc_MlKemKey_EncapsulateWithRandom(
        &key,
        ciphertext,
        shared_secret,
        m,
        WC_ML_KEM_ENC_RAND_SZ
    );

    if (rc != 0) {
        fprintf(
            stderr,
            "EncapsulateWithRandom failed: %d\n",
            rc
        );
        goto cleanup;
    }

    print_hex(
        "ciphertext",
        ciphertext,
        ciphertext_size
    );

    print_hex(
        "shared_secret",
        shared_secret,
        shared_secret_size
    );

    rc = 0;

cleanup:

    if (initialized) {
        (void)wc_MlKemKey_Free(&key);
    }

    free(public_key);
    free(m);
    free(ciphertext);
    free(shared_secret);

    return rc;
}

static int kem_decaps(
    const MlKemParams *params,
    const char *secret_key_hex,
    const char *ciphertext_hex
)
{
    MlKemKey key;

    unsigned char *secret_key = NULL;
    unsigned char *ciphertext = NULL;
    unsigned char *shared_secret = NULL;

    word32 public_key_size = 0;
    word32 private_key_size = 0;
    word32 ciphertext_size = 0;
    word32 shared_secret_size = 0;

    int initialized = 0;
    int rc = 1;

    rc = init_key(&key, params->type);
    if (rc != 0) goto cleanup;

    initialized = 1;

    rc = query_sizes(
        &key,
        &public_key_size,
        &private_key_size,
        &ciphertext_size,
        &shared_secret_size
    );

    if (rc != 0) goto cleanup;

    secret_key = from_hex(
        secret_key_hex,
        private_key_size
    );

    ciphertext = from_hex(
        ciphertext_hex,
        ciphertext_size
    );

    if (
        secret_key == NULL ||
        ciphertext == NULL
    ) {
        fprintf(stderr, "invalid decapsulation input\n");
        rc = 1;
        goto cleanup;
    }

    shared_secret = (unsigned char *)malloc(
        shared_secret_size
    );

    if (shared_secret == NULL) {
        fprintf(stderr, "allocation failure\n");
        rc = 1;
        goto cleanup;
    }

    rc = wc_MlKemKey_DecodePrivateKey(
        &key,
        secret_key,
        private_key_size
    );

    if (rc != 0) {
        fprintf(
            stderr,
            "DecodePrivateKey failed: %d\n",
            rc
        );
        goto cleanup;
    }

    rc = wc_MlKemKey_Decapsulate(
        &key,
        shared_secret,
        ciphertext,
        ciphertext_size
    );

    if (rc != 0) {
        fprintf(
            stderr,
            "Decapsulate failed: %d\n",
            rc
        );
        goto cleanup;
    }

    print_hex(
        "shared_secret",
        shared_secret,
        shared_secret_size
    );

    rc = 0;

cleanup:

    if (initialized) {
        (void)wc_MlKemKey_Free(&key);
    }

    free(secret_key);
    free(ciphertext);
    free(shared_secret);

    return rc;
}


typedef struct {
    byte level;
    const char *name;
    word32 public_key_size;
    word32 private_key_size;
    word32 signature_size;
} DsaBridgeParams;

static int get_dsa_params(
    const char *name,
    DsaBridgeParams *params
)
{
    if (strcmp(name, "ML-DSA-44") == 0) {
        params->level = WC_ML_DSA_44;
        params->name = "ML-DSA-44";
        params->public_key_size = WC_MLDSA_44_PUB_KEY_SIZE;
        params->private_key_size = WC_MLDSA_44_KEY_SIZE;
        params->signature_size = WC_MLDSA_44_SIG_SIZE;
        return 0;
    }

    if (strcmp(name, "ML-DSA-65") == 0) {
        params->level = WC_ML_DSA_65;
        params->name = "ML-DSA-65";
        params->public_key_size = WC_MLDSA_65_PUB_KEY_SIZE;
        params->private_key_size = WC_MLDSA_65_KEY_SIZE;
        params->signature_size = WC_MLDSA_65_SIG_SIZE;
        return 0;
    }

    if (strcmp(name, "ML-DSA-87") == 0) {
        params->level = WC_ML_DSA_87;
        params->name = "ML-DSA-87";
        params->public_key_size = WC_MLDSA_87_PUB_KEY_SIZE;
        params->private_key_size = WC_MLDSA_87_KEY_SIZE;
        params->signature_size = WC_MLDSA_87_SIG_SIZE;
        return 0;
    }

    return -1;
}

static unsigned char *from_hex_variable(
    const char *hex,
    size_t *out_len
)
{
    size_t hex_len;
    size_t len;
    unsigned char *out;
    size_t i;

    if (hex == NULL || out_len == NULL) {
        return NULL;
    }

    hex_len = strlen(hex);

    if ((hex_len & 1U) != 0U) {
        return NULL;
    }

    len = hex_len / 2U;

    out = (unsigned char *)malloc(
        len == 0U ? 1U : len
    );

    if (out == NULL) {
        return NULL;
    }

    for (i = 0; i < len; i++) {
        unsigned int value;

        if (sscanf(
                hex + (2U * i),
                "%2x",
                &value
            ) != 1) {
            free(out);
            return NULL;
        }

        out[i] = (unsigned char)value;
    }

    *out_len = len;
    return out;
}

static int init_dsa_key(
    wc_MlDsaKey *key,
    const DsaBridgeParams *params
)
{
    int rc;

    rc = wc_MlDsaKey_Init(
        key,
        NULL,
        INVALID_DEVID
    );

    if (rc != 0) {
        fprintf(
            stderr,
            "wc_MlDsaKey_Init failed: %d\n",
            rc
        );
        return rc;
    }

    rc = wc_MlDsaKey_SetParams(
        key,
        params->level
    );

    if (rc != 0) {
        fprintf(
            stderr,
            "wc_MlDsaKey_SetParams failed: %d\n",
            rc
        );
        wc_MlDsaKey_Free(key);
        return rc;
    }

    return 0;
}

static int dsa_keygen_bridge(
    const DsaBridgeParams *params,
    const char *xi_hex
)
{
    wc_MlDsaKey key;
    unsigned char *xi = NULL;
    unsigned char *public_key = NULL;
    unsigned char *private_key = NULL;

    word32 public_key_len;
    word32 private_key_len;

    int initialized = 0;
    int rc = 1;

    xi = from_hex(xi_hex, 32U);

    if (xi == NULL) {
        fprintf(
            stderr,
            "xi must be exactly 32 bytes\n"
        );
        goto cleanup;
    }

    public_key = (unsigned char *)malloc(
        params->public_key_size
    );

    private_key = (unsigned char *)malloc(
        params->private_key_size
    );

    if (public_key == NULL || private_key == NULL) {
        fprintf(stderr, "allocation failure\n");
        goto cleanup;
    }

    rc = init_dsa_key(&key, params);

    if (rc != 0) {
        goto cleanup;
    }

    initialized = 1;

    rc = wc_MlDsaKey_MakeKeyFromSeed(
        &key,
        xi
    );

    if (rc != 0) {
        fprintf(
            stderr,
            "wc_MlDsaKey_MakeKeyFromSeed failed: %d\n",
            rc
        );
        goto cleanup;
    }

    public_key_len = params->public_key_size;

    rc = wc_MlDsaKey_ExportPubRaw(
        &key,
        public_key,
        &public_key_len
    );

    if (rc != 0) {
        fprintf(
            stderr,
            "wc_MlDsaKey_ExportPubRaw failed: %d\n",
            rc
        );
        goto cleanup;
    }

    private_key_len = params->private_key_size;

    rc = wc_MlDsaKey_ExportPrivRaw(
        &key,
        private_key,
        &private_key_len
    );

    if (rc != 0) {
        fprintf(
            stderr,
            "wc_MlDsaKey_ExportPrivRaw failed: %d\n",
            rc
        );
        goto cleanup;
    }

    if (
        public_key_len != params->public_key_size ||
        private_key_len != params->private_key_size
    ) {
        fprintf(
            stderr,
            "unexpected ML-DSA raw key size\n"
        );
        rc = 1;
        goto cleanup;
    }

    print_hex(
        "public_key",
        public_key,
        public_key_len
    );

    print_hex(
        "secret_key",
        private_key,
        private_key_len
    );

    rc = 0;

cleanup:

    if (initialized) {
        wc_MlDsaKey_Free(&key);
    }

    free(xi);
    free(public_key);
    free(private_key);

    return rc;
}

static int dsa_sign_bridge(
    const DsaBridgeParams *params,
    const char *secret_key_hex,
    const char *message_hex,
    const char *context_hex,
    const char *randomness_hex
)
{
    wc_MlDsaKey key;

    unsigned char *secret_key = NULL;
    unsigned char *message = NULL;
    unsigned char *context = NULL;
    unsigned char *randomness = NULL;
    unsigned char *signature = NULL;

    size_t message_len = 0;
    size_t context_len = 0;

    word32 signature_len;

    int initialized = 0;
    int rc = 1;

    secret_key = from_hex(
        secret_key_hex,
        params->private_key_size
    );

    randomness = from_hex(
        randomness_hex,
        32U
    );

    message = from_hex_variable(
        message_hex,
        &message_len
    );

    context = from_hex_variable(
        context_hex,
        &context_len
    );

    if (
        secret_key == NULL ||
        randomness == NULL ||
        message == NULL ||
        context == NULL
    ) {
        fprintf(stderr, "invalid ML-DSA signing input\n");
        goto cleanup;
    }

    if (context_len > 255U) {
        fprintf(stderr, "ML-DSA context exceeds 255 bytes\n");
        goto cleanup;
    }

    if (message_len > 0xffffffffU) {
        fprintf(stderr, "ML-DSA message too large\n");
        goto cleanup;
    }

    signature = (unsigned char *)malloc(
        params->signature_size
    );

    if (signature == NULL) {
        fprintf(stderr, "allocation failure\n");
        goto cleanup;
    }

    rc = init_dsa_key(&key, params);

    if (rc != 0) {
        goto cleanup;
    }

    initialized = 1;

    rc = wc_MlDsaKey_ImportPrivRaw(
        &key,
        secret_key,
        params->private_key_size
    );

    if (rc != 0) {
        fprintf(
            stderr,
            "wc_MlDsaKey_ImportPrivRaw failed: %d\n",
            rc
        );
        goto cleanup;
    }

    signature_len = params->signature_size;

    rc = wc_MlDsaKey_SignCtxWithSeed(
        &key,
        context,
        (byte)context_len,
        signature,
        &signature_len,
        message,
        (word32)message_len,
        randomness
    );

    if (rc != 0) {
        fprintf(
            stderr,
            "wc_MlDsaKey_SignCtxWithSeed failed: %d\n",
            rc
        );
        goto cleanup;
    }

    if (signature_len != params->signature_size) {
        fprintf(
            stderr,
            "unexpected ML-DSA signature size\n"
        );
        rc = 1;
        goto cleanup;
    }

    print_hex(
        "signature",
        signature,
        signature_len
    );

    rc = 0;

cleanup:

    if (initialized) {
        wc_MlDsaKey_Free(&key);
    }

    free(secret_key);
    free(message);
    free(context);
    free(randomness);
    free(signature);

    return rc;
}

static int dsa_verify_bridge(
    const DsaBridgeParams *params,
    const char *public_key_hex,
    const char *message_hex,
    const char *context_hex,
    const char *signature_hex
)
{
    wc_MlDsaKey key;

    unsigned char *public_key = NULL;
    unsigned char *message = NULL;
    unsigned char *context = NULL;
    unsigned char *signature = NULL;

    size_t message_len = 0;
    size_t context_len = 0;

    int initialized = 0;
    int verify_result = 0;
    int rc = 1;

    public_key = from_hex(
        public_key_hex,
        params->public_key_size
    );

    signature = from_hex(
        signature_hex,
        params->signature_size
    );

    message = from_hex_variable(
        message_hex,
        &message_len
    );

    context = from_hex_variable(
        context_hex,
        &context_len
    );

    if (
        public_key == NULL ||
        signature == NULL ||
        message == NULL ||
        context == NULL
    ) {
        fprintf(stderr, "invalid ML-DSA verification input\n");
        goto cleanup;
    }

    if (context_len > 255U) {
        fprintf(stderr, "ML-DSA context exceeds 255 bytes\n");
        goto cleanup;
    }

    if (message_len > 0xffffffffU) {
        fprintf(stderr, "ML-DSA message too large\n");
        goto cleanup;
    }

    rc = init_dsa_key(&key, params);

    if (rc != 0) {
        goto cleanup;
    }

    initialized = 1;

    rc = wc_MlDsaKey_ImportPubRaw(
        &key,
        public_key,
        params->public_key_size
    );

    if (rc != 0) {
        fprintf(
            stderr,
            "wc_MlDsaKey_ImportPubRaw failed: %d\n",
            rc
        );
        goto cleanup;
    }

    rc = wc_MlDsaKey_VerifyCtx(
        &key,
        signature,
        params->signature_size,
        context,
        (byte)context_len,
        message,
        (word32)message_len,
        &verify_result
    );

    /*
     * For W2.1, a successful API call may report either a
     * valid or invalid signature through verify_result.
     */
    if (rc != 0) {
        fprintf(
            stderr,
            "wc_MlDsaKey_VerifyCtx failed: %d\n",
            rc
        );
        goto cleanup;
    }

    printf(
        "valid=%s\n",
        verify_result == 1 ? "true" : "false"
    );

    rc = 0;

cleanup:

    if (initialized) {
        wc_MlDsaKey_Free(&key);
    }

    free(public_key);
    free(message);
    free(context);
    free(signature);

    return rc;
}

int main(int argc, char **argv)
{
    MlKemParams kem_params;
    DsaBridgeParams dsa_params;

    if (argc < 3) {
        fprintf(
            stderr,
            "usage: wolfssl_bridge OP PARAMETER_SET [ARGS]\n"
        );
        return 64;
    }

    if (strncmp(argv[1], "kem-", 4) == 0) {

        if (get_params(argv[2], &kem_params) != 0) {
            fprintf(
                stderr,
                "unsupported KEM parameter set: %s\n",
                argv[2]
            );
            return 65;
        }

        if (strcmp(argv[1], "kem-keygen") == 0) {
            if (argc != 5) return 64;

            return kem_keygen(
                &kem_params,
                argv[3],
                argv[4]
            );
        }

        if (strcmp(argv[1], "kem-encaps") == 0) {
            if (argc != 5) return 64;

            return kem_encaps(
                &kem_params,
                argv[3],
                argv[4]
            );
        }

        if (strcmp(argv[1], "kem-decaps") == 0) {
            if (argc != 5) return 64;

            return kem_decaps(
                &kem_params,
                argv[3],
                argv[4]
            );
        }
    }

    if (strncmp(argv[1], "dsa-", 4) == 0) {

        if (get_dsa_params(argv[2], &dsa_params) != 0) {
            fprintf(
                stderr,
                "unsupported DSA parameter set: %s\n",
                argv[2]
            );
            return 65;
        }

        if (strcmp(argv[1], "dsa-keygen") == 0) {
            if (argc != 4) return 64;

            return dsa_keygen_bridge(
                &dsa_params,
                argv[3]
            );
        }

        if (strcmp(argv[1], "dsa-sign") == 0) {
            if (argc != 7) return 64;

            return dsa_sign_bridge(
                &dsa_params,
                argv[3],
                argv[4],
                argv[5],
                argv[6]
            );
        }

        if (strcmp(argv[1], "dsa-verify") == 0) {
            if (argc != 7) return 64;

            return dsa_verify_bridge(
                &dsa_params,
                argv[3],
                argv[4],
                argv[5],
                argv[6]
            );
        }
    }

    fprintf(
        stderr,
        "unsupported operation: %s\n",
        argv[1]
    );

    return 65;
}
