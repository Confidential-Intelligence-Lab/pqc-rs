#include <oqs/oqs.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned char *from_hex(const char *s, size_t *n)
{
    size_t len = strlen(s);

    if ((len % 2) != 0) {
        return NULL;
    }

    *n = len / 2;

    unsigned char *b = malloc(*n ? *n : 1);
    if (b == NULL) {
        return NULL;
    }

    for (size_t i = 0; i < *n; i++) {
        unsigned int x;

        if (sscanf(s + (2 * i), "%2x", &x) != 1) {
            free(b);
            return NULL;
        }

        b[i] = (unsigned char)x;
    }

    return b;
}

static void print_hex(
    const char *key,
    const unsigned char *bytes,
    size_t length)
{
    printf("%s=", key);

    for (size_t i = 0; i < length; i++) {
        printf("%02x", bytes[i]);
    }

    printf("\n");
}

static int kem(
    const char *op,
    const char *alg,
    int argc,
    char **argv)
{
    OQS_KEM *kem = OQS_KEM_new(alg);
    int rc = 1;

    if (kem == NULL) {
        return 2;
    }

    if (strcmp(op, "kem-keygen") == 0 && argc >= 5) {
        size_t d_len;
        size_t z_len;

        unsigned char *d = from_hex(argv[3], &d_len);
        unsigned char *z = from_hex(argv[4], &z_len);

        unsigned char *public_key = malloc(kem->length_public_key);
        unsigned char *secret_key = malloc(kem->length_secret_key);

        if (d != NULL &&
            z != NULL &&
            public_key != NULL &&
            secret_key != NULL &&
            d_len == 32 &&
            z_len == 32 &&
            kem->length_keypair_seed == 64) {

            unsigned char seed[64];

            memcpy(seed, d, 32);
            memcpy(seed + 32, z, 32);

            if (OQS_KEM_keypair_derand(
                    kem,
                    public_key,
                    secret_key,
                    seed) == OQS_SUCCESS) {

                print_hex(
                    "public_key",
                    public_key,
                    kem->length_public_key);

                print_hex(
                    "secret_key",
                    secret_key,
                    kem->length_secret_key);

                rc = 0;
            }
        }

        free(d);
        free(z);
        free(public_key);
        free(secret_key);
    } else if (
        strcmp(op, "kem-encaps") == 0 &&
        argc >= 5) {

        size_t public_key_len;
        size_t m_len;

        unsigned char *public_key =
            from_hex(argv[3], &public_key_len);

        unsigned char *m =
            from_hex(argv[4], &m_len);

        unsigned char *ciphertext =
            malloc(kem->length_ciphertext);

        unsigned char *shared_secret =
            malloc(kem->length_shared_secret);

        if (public_key != NULL &&
            m != NULL &&
            ciphertext != NULL &&
            shared_secret != NULL &&
            public_key_len == kem->length_public_key &&
            m_len == 32 &&
            kem->length_encaps_seed == 32 &&
            OQS_KEM_encaps_derand(
                kem,
                ciphertext,
                shared_secret,
                public_key,
                m) == OQS_SUCCESS) {

            print_hex(
                "ciphertext",
                ciphertext,
                kem->length_ciphertext);

            print_hex(
                "shared_secret",
                shared_secret,
                kem->length_shared_secret);

            rc = 0;
        }

        free(public_key);
        free(m);
        free(ciphertext);
        free(shared_secret);
    } else if (
        strcmp(op, "kem-decaps") == 0 &&
        argc >= 5) {

        size_t secret_key_len;
        size_t ciphertext_len;

        unsigned char *secret_key =
            from_hex(argv[3], &secret_key_len);

        unsigned char *ciphertext =
            from_hex(argv[4], &ciphertext_len);

        unsigned char *shared_secret =
            malloc(kem->length_shared_secret);

        if (secret_key != NULL &&
            ciphertext != NULL &&
            shared_secret != NULL &&
            secret_key_len == kem->length_secret_key &&
            ciphertext_len == kem->length_ciphertext &&
            OQS_KEM_decaps(
                kem,
                shared_secret,
                ciphertext,
                secret_key) == OQS_SUCCESS) {

            print_hex(
                "shared_secret",
                shared_secret,
                kem->length_shared_secret);

            rc = 0;
        }

        free(secret_key);
        free(ciphertext);
        free(shared_secret);
    }

    OQS_KEM_free(kem);
    return rc;
}

static const char *sig_alg_name(const char *alg)
{
    if (strcmp(alg, "SLH-DSA-SHA2-128s") == 0) {
        return OQS_SIG_alg_slh_dsa_pure_sha2_128s;
    }
    if (strcmp(alg, "SLH-DSA-SHA2-128f") == 0) {
        return OQS_SIG_alg_slh_dsa_pure_sha2_128f;
    }
    if (strcmp(alg, "SLH-DSA-SHA2-192s") == 0) {
        return OQS_SIG_alg_slh_dsa_pure_sha2_192s;
    }
    if (strcmp(alg, "SLH-DSA-SHA2-192f") == 0) {
        return OQS_SIG_alg_slh_dsa_pure_sha2_192f;
    }
    if (strcmp(alg, "SLH-DSA-SHA2-256s") == 0) {
        return OQS_SIG_alg_slh_dsa_pure_sha2_256s;
    }
    if (strcmp(alg, "SLH-DSA-SHA2-256f") == 0) {
        return OQS_SIG_alg_slh_dsa_pure_sha2_256f;
    }
    if (strcmp(alg, "SLH-DSA-SHAKE-128s") == 0) {
        return OQS_SIG_alg_slh_dsa_pure_shake_128s;
    }
    if (strcmp(alg, "SLH-DSA-SHAKE-128f") == 0) {
        return OQS_SIG_alg_slh_dsa_pure_shake_128f;
    }
    if (strcmp(alg, "SLH-DSA-SHAKE-192s") == 0) {
        return OQS_SIG_alg_slh_dsa_pure_shake_192s;
    }
    if (strcmp(alg, "SLH-DSA-SHAKE-192f") == 0) {
        return OQS_SIG_alg_slh_dsa_pure_shake_192f;
    }
    if (strcmp(alg, "SLH-DSA-SHAKE-256s") == 0) {
        return OQS_SIG_alg_slh_dsa_pure_shake_256s;
    }
    if (strcmp(alg, "SLH-DSA-SHAKE-256f") == 0) {
        return OQS_SIG_alg_slh_dsa_pure_shake_256f;
    }

    return alg;
}

static const char *hash_sig_alg_name(
    const char *alg,
    const char *prehash)
{
    const char *family = NULL;
    const char *level = NULL;
    const char *speed = NULL;
    const char *ph = NULL;
    const char *suffix;
    static char name[96];

    if (strncmp(alg, "SLH-DSA-SHA2-", 13) == 0) {
        family = "SHA2";
    } else if (strncmp(alg, "SLH-DSA-SHAKE-", 14) == 0) {
        family = "SHAKE";
    } else {
        return NULL;
    }

    suffix = strrchr(alg, '-');
    if (suffix == NULL || strlen(suffix + 1) < 4) {
        return NULL;
    }

    if (strncmp(suffix + 1, "128", 3) == 0) {
        level = "128";
    } else if (strncmp(suffix + 1, "192", 3) == 0) {
        level = "192";
    } else if (strncmp(suffix + 1, "256", 3) == 0) {
        level = "256";
    } else {
        return NULL;
    }

    if (suffix[strlen(suffix) - 1] == 's') {
        speed = "S";
    } else if (suffix[strlen(suffix) - 1] == 'f') {
        speed = "F";
    } else {
        return NULL;
    }

    if (strcmp(prehash, "SHA2-224") == 0) {
        ph = "SHA2_224";
    } else if (strcmp(prehash, "SHA2-256") == 0) {
        ph = "SHA2_256";
    } else if (strcmp(prehash, "SHA2-384") == 0) {
        ph = "SHA2_384";
    } else if (strcmp(prehash, "SHA2-512") == 0) {
        ph = "SHA2_512";
    } else if (strcmp(prehash, "SHA2-512/224") == 0) {
        ph = "SHA2_512_224";
    } else if (strcmp(prehash, "SHA2-512/256") == 0) {
        ph = "SHA2_512_256";
    } else if (strcmp(prehash, "SHA3-224") == 0) {
        ph = "SHA3_224";
    } else if (strcmp(prehash, "SHA3-256") == 0) {
        ph = "SHA3_256";
    } else if (strcmp(prehash, "SHA3-384") == 0) {
        ph = "SHA3_384";
    } else if (strcmp(prehash, "SHA3-512") == 0) {
        ph = "SHA3_512";
    } else if (strcmp(prehash, "SHAKE-128") == 0) {
        ph = "SHAKE_128";
    } else if (strcmp(prehash, "SHAKE-256") == 0) {
        ph = "SHAKE_256";
    } else {
        return NULL;
    }

    snprintf(
        name,
        sizeof(name),
        "SLH_DSA_%s_PREHASH_%s_%s%s",
        ph,
        family,
        level,
        speed);

    return name;
}

static int sig(
    const char *op,
    const char *alg,
    int argc,
    char **argv)
{
    const char *selected_alg = sig_alg_name(alg);
    OQS_SIG *sig;
    int rc = 1;

    if (strcmp(op, "slh-hash-sign") == 0 && argc >= 7) {
        selected_alg = hash_sig_alg_name(alg, argv[6]);
    } else if (strcmp(op, "slh-hash-verify") == 0 && argc >= 8) {
        selected_alg = hash_sig_alg_name(alg, argv[7]);
    }

    if (selected_alg == NULL) {
        return 2;
    }

    sig = OQS_SIG_new(selected_alg);

    if (sig == NULL) {
        return 2;
    }

    if (strcmp(op, "dsa-keygen") == 0 ||
        strcmp(op, "slh-keygen") == 0) {
        unsigned char *public_key =
            malloc(sig->length_public_key);

        unsigned char *secret_key =
            malloc(sig->length_secret_key);

        if (public_key != NULL &&
            secret_key != NULL &&
            OQS_SIG_keypair(
                sig,
                public_key,
                secret_key) == OQS_SUCCESS) {

            print_hex(
                "public_key",
                public_key,
                sig->length_public_key);

            print_hex(
                "secret_key",
                secret_key,
                sig->length_secret_key);

            rc = 0;
        }

        free(public_key);
        free(secret_key);
    } else if (
        (strcmp(op, "dsa-sign") == 0 ||
         strcmp(op, "slh-sign") == 0 ||
         strcmp(op, "slh-hash-sign") == 0) &&
        argc >= 6) {

        size_t secret_key_len;
        size_t message_len;
        size_t context_len;

        unsigned char *secret_key =
            from_hex(argv[3], &secret_key_len);

        unsigned char *message =
            from_hex(argv[4], &message_len);

        unsigned char *context =
            from_hex(argv[5], &context_len);

        unsigned char *signature =
            malloc(sig->length_signature);

        size_t signature_len = 0;

        if (secret_key != NULL &&
            message != NULL &&
            context != NULL &&
            signature != NULL &&
            secret_key_len == sig->length_secret_key &&
            OQS_SIG_sign_with_ctx_str(
                sig,
                signature,
                &signature_len,
                message,
                message_len,
                context,
                context_len,
                secret_key) == OQS_SUCCESS) {

            print_hex(
                "signature",
                signature,
                signature_len);

            rc = 0;
        }

        free(secret_key);
        free(message);
        free(context);
        free(signature);
    } else if (
        (strcmp(op, "dsa-verify") == 0 ||
         strcmp(op, "slh-verify") == 0 ||
         strcmp(op, "slh-hash-verify") == 0) &&
        argc >= 7) {

        size_t public_key_len;
        size_t message_len;
        size_t context_len;
        size_t signature_len;

        unsigned char *public_key =
            from_hex(argv[3], &public_key_len);

        unsigned char *message =
            from_hex(argv[4], &message_len);

        unsigned char *context =
            from_hex(argv[5], &context_len);

        unsigned char *signature =
            from_hex(argv[6], &signature_len);

        if (public_key != NULL &&
            message != NULL &&
            context != NULL &&
            signature != NULL &&
            public_key_len == sig->length_public_key) {

            OQS_STATUS status =
                OQS_SIG_verify_with_ctx_str(
                    sig,
                    message,
                    message_len,
                    signature,
                    signature_len,
                    context,
                    context_len,
                    public_key);

            printf(
                "valid=%s\n",
                status == OQS_SUCCESS ? "true" : "false");

            rc = 0;
        }

        free(public_key);
        free(message);
        free(context);
        free(signature);
    }

    OQS_SIG_free(sig);
    return rc;
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        return 64;
    }

    if (strncmp(argv[2], "ML-KEM", 6) == 0) {
        return kem(argv[1], argv[2], argc, argv);
    }

    if (strncmp(argv[2], "ML-DSA", 6) == 0 ||
        strncmp(argv[2], "SLH-DSA", 7) == 0) {
        return sig(argv[1], argv[2], argc, argv);
    }

    return 65;
}
