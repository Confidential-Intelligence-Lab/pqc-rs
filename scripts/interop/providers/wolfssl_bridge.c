#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/wc_mlkem.h>

static unsigned char *from_hex(
    const char *hex,
    size_t expected_len
)
{
    size_t hex_len;
    unsigned char *out;
    size_t i;

    if (hex == NULL) {
        return NULL;
    }

    hex_len = strlen(hex);

    if (hex_len != expected_len * 2U) {
        return NULL;
    }

    out = (unsigned char *)malloc(expected_len == 0U ? 1U : expected_len);

    if (out == NULL) {
        return NULL;
    }

    for (i = 0; i < expected_len; i++) {
        unsigned int value;

        if (sscanf(hex + (2U * i), "%2x", &value) != 1) {
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

static int init_mlkem768(MlKemKey *key)
{
    int rc;

    rc = wc_MlKemKey_Init(
        key,
        WC_ML_KEM_768,
        NULL,
        INVALID_DEVID
    );

    if (rc != 0) {
        fprintf(
            stderr,
            "wc_MlKemKey_Init failed: %d\n",
            rc
        );
        return rc;
    }

    return 0;
}

static int kem_keygen(
    const char *d_hex,
    const char *z_hex
)
{
    MlKemKey key;
    unsigned char *d = NULL;
    unsigned char *z = NULL;

    unsigned char randomness[WC_ML_KEM_MAKEKEY_RAND_SZ];

    unsigned char public_key[
        WC_ML_KEM_768_PUBLIC_KEY_SIZE
    ];

    unsigned char private_key[
        WC_ML_KEM_768_PRIVATE_KEY_SIZE
    ];

    int initialized = 0;
    int rc = 1;

    d = from_hex(d_hex, WC_ML_KEM_SYM_SZ);
    z = from_hex(z_hex, WC_ML_KEM_SYM_SZ);

    if (d == NULL || z == NULL) {
        fprintf(
            stderr,
            "d and z must each be exactly 32 bytes of hex\n"
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

    rc = init_mlkem768(&key);

    if (rc != 0) {
        goto cleanup;
    }

    initialized = 1;

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
        sizeof(public_key)
    );

    if (rc != 0) {
        fprintf(
            stderr,
            "wc_MlKemKey_EncodePublicKey failed: %d\n",
            rc
        );
        goto cleanup;
    }

    rc = wc_MlKemKey_EncodePrivateKey(
        &key,
        private_key,
        sizeof(private_key)
    );

    if (rc != 0) {
        fprintf(
            stderr,
            "wc_MlKemKey_EncodePrivateKey failed: %d\n",
            rc
        );
        goto cleanup;
    }

    print_hex(
        "public_key",
        public_key,
        sizeof(public_key)
    );

    print_hex(
        "secret_key",
        private_key,
        sizeof(private_key)
    );

    rc = 0;

cleanup:

    if (initialized) {
        int free_rc = wc_MlKemKey_Free(&key);

        if (free_rc != 0 && rc == 0) {
            fprintf(
                stderr,
                "wc_MlKemKey_Free failed: %d\n",
                free_rc
            );
            rc = free_rc;
        }
    }

    free(d);
    free(z);

    return rc;
}

static int kem_encaps(
    const char *public_key_hex,
    const char *m_hex
)
{
    MlKemKey key;

    unsigned char *public_key = NULL;
    unsigned char *m = NULL;

    unsigned char ciphertext[
        WC_ML_KEM_768_CIPHER_TEXT_SIZE
    ];

    unsigned char shared_secret[
        WC_ML_KEM_SS_SZ
    ];

    int initialized = 0;
    int rc = 1;

    public_key = from_hex(
        public_key_hex,
        WC_ML_KEM_768_PUBLIC_KEY_SIZE
    );

    m = from_hex(
        m_hex,
        WC_ML_KEM_ENC_RAND_SZ
    );

    if (public_key == NULL) {
        fprintf(
            stderr,
            "public_key must be exactly 1184 bytes of hex\n"
        );
        goto cleanup;
    }

    if (m == NULL) {
        fprintf(
            stderr,
            "m must be exactly 32 bytes of hex\n"
        );
        goto cleanup;
    }

    rc = init_mlkem768(&key);

    if (rc != 0) {
        goto cleanup;
    }

    initialized = 1;

    rc = wc_MlKemKey_DecodePublicKey(
        &key,
        public_key,
        WC_ML_KEM_768_PUBLIC_KEY_SIZE
    );

    if (rc != 0) {
        fprintf(
            stderr,
            "wc_MlKemKey_DecodePublicKey failed: %d\n",
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
            "wc_MlKemKey_EncapsulateWithRandom failed: %d\n",
            rc
        );
        goto cleanup;
    }

    print_hex(
        "ciphertext",
        ciphertext,
        sizeof(ciphertext)
    );

    print_hex(
        "shared_secret",
        shared_secret,
        sizeof(shared_secret)
    );

    rc = 0;

cleanup:

    if (initialized) {
        int free_rc = wc_MlKemKey_Free(&key);

        if (free_rc != 0 && rc == 0) {
            fprintf(
                stderr,
                "wc_MlKemKey_Free failed: %d\n",
                free_rc
            );
            rc = free_rc;
        }
    }

    free(public_key);
    free(m);

    return rc;
}

static int kem_decaps(
    const char *secret_key_hex,
    const char *ciphertext_hex
)
{
    MlKemKey key;

    unsigned char *secret_key = NULL;
    unsigned char *ciphertext = NULL;

    unsigned char shared_secret[
        WC_ML_KEM_SS_SZ
    ];

    int initialized = 0;
    int rc = 1;

    secret_key = from_hex(
        secret_key_hex,
        WC_ML_KEM_768_PRIVATE_KEY_SIZE
    );

    ciphertext = from_hex(
        ciphertext_hex,
        WC_ML_KEM_768_CIPHER_TEXT_SIZE
    );

    if (secret_key == NULL) {
        fprintf(
            stderr,
            "secret_key must be exactly 2400 bytes of hex\n"
        );
        goto cleanup;
    }

    if (ciphertext == NULL) {
        fprintf(
            stderr,
            "ciphertext must be exactly 1088 bytes of hex\n"
        );
        goto cleanup;
    }

    rc = init_mlkem768(&key);

    if (rc != 0) {
        goto cleanup;
    }

    initialized = 1;

    rc = wc_MlKemKey_DecodePrivateKey(
        &key,
        secret_key,
        WC_ML_KEM_768_PRIVATE_KEY_SIZE
    );

    if (rc != 0) {
        fprintf(
            stderr,
            "wc_MlKemKey_DecodePrivateKey failed: %d\n",
            rc
        );
        goto cleanup;
    }

    rc = wc_MlKemKey_Decapsulate(
        &key,
        shared_secret,
        ciphertext,
        WC_ML_KEM_768_CIPHER_TEXT_SIZE
    );

    if (rc != 0) {
        fprintf(
            stderr,
            "wc_MlKemKey_Decapsulate failed: %d\n",
            rc
        );
        goto cleanup;
    }

    print_hex(
        "shared_secret",
        shared_secret,
        sizeof(shared_secret)
    );

    rc = 0;

cleanup:

    if (initialized) {
        int free_rc = wc_MlKemKey_Free(&key);

        if (free_rc != 0 && rc == 0) {
            fprintf(
                stderr,
                "wc_MlKemKey_Free failed: %d\n",
                free_rc
            );
            rc = free_rc;
        }
    }

    free(secret_key);
    free(ciphertext);

    return rc;
}

int main(int argc, char **argv)
{
    const char *operation;
    const char *parameter_set;

    if (argc < 3) {
        fprintf(
            stderr,
            "usage: wolfssl_bridge OPERATION PARAMETER_SET [ARGS]\n"
        );
        return 64;
    }

    operation = argv[1];
    parameter_set = argv[2];

    if (strcmp(parameter_set, "ML-KEM-768") != 0) {
        fprintf(
            stderr,
            "unsupported parameter set: %s\n",
            parameter_set
        );
        return 65;
    }

    if (strcmp(operation, "kem-keygen") == 0) {
        if (argc != 5) {
            fprintf(
                stderr,
                "kem-keygen requires d and z\n"
            );
            return 64;
        }

        return kem_keygen(
            argv[3],
            argv[4]
        );
    }

    if (strcmp(operation, "kem-encaps") == 0) {
        if (argc != 5) {
            fprintf(
                stderr,
                "kem-encaps requires public_key and m\n"
            );
            return 64;
        }

        return kem_encaps(
            argv[3],
            argv[4]
        );
    }

    if (strcmp(operation, "kem-decaps") == 0) {
        if (argc != 5) {
            fprintf(
                stderr,
                "kem-decaps requires secret_key and ciphertext\n"
            );
            return 64;
        }

        return kem_decaps(
            argv[3],
            argv[4]
        );
    }

    fprintf(
        stderr,
        "unsupported operation: %s\n",
        operation
    );

    return 65;
}
