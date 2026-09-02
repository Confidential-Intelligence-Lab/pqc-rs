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

static int sig(
    const char *op,
    const char *alg,
    int argc,
    char **argv)
{
    OQS_SIG *sig = OQS_SIG_new(alg);
    int rc = 1;

    if (sig == NULL) {
        return 2;
    }

    if (strcmp(op, "dsa-keygen") == 0) {
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
        strcmp(op, "dsa-sign") == 0 &&
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
        strcmp(op, "dsa-verify") == 0 &&
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

    if (strncmp(argv[2], "ML-DSA", 6) == 0) {
        return sig(argv[1], argv[2], argc, argv);
    }

    return 65;
}
