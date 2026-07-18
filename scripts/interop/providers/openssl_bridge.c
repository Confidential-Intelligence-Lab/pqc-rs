#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>
#include <openssl/params.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned char *from_hex(const char *s, size_t *n) {
    size_t len = strlen(s);
    if ((len & 1U) != 0U) return NULL;
    *n = len / 2U;
    unsigned char *b = malloc(*n == 0U ? 1U : *n);
    if (b == NULL) return NULL;
    for (size_t i = 0; i < *n; i++) {
        unsigned int x = 0;
        if (sscanf(s + (2U * i), "%2x", &x) != 1) { free(b); return NULL; }
        b[i] = (unsigned char)x;
    }
    return b;
}

static void print_hex(const char *name, const unsigned char *b, size_t n) {
    printf("%s=", name);
    for (size_t i = 0; i < n; i++) printf("%02x", b[i]);
    putchar('\n');
}

static EVP_PKEY *import_key(const char *alg,
                            unsigned char *pub, size_t pub_len,
                            unsigned char *priv, size_t priv_len) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, alg, NULL);
    EVP_PKEY *key = NULL;
    OSSL_PARAM params[3];
    size_t i = 0;
    if (ctx == NULL || EVP_PKEY_fromdata_init(ctx) <= 0) goto done;
    if (pub != NULL) params[i++] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, pub, pub_len);
    if (priv != NULL) params[i++] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, priv, priv_len);
    params[i] = OSSL_PARAM_construct_end();
    int selection = priv != NULL ? EVP_PKEY_KEYPAIR : EVP_PKEY_PUBLIC_KEY;
    if (EVP_PKEY_fromdata(ctx, &key, selection, params) <= 0) key = NULL;
done:
    EVP_PKEY_CTX_free(ctx);
    return key;
}

static int export_component(EVP_PKEY *key, const char *name, const char *label) {
    size_t n = 0;
    if (EVP_PKEY_get_octet_string_param(key, name, NULL, 0, &n) <= 0) return 0;
    unsigned char *buf = malloc(n == 0U ? 1U : n);
    if (buf == NULL) return 0;
    int ok = EVP_PKEY_get_octet_string_param(key, name, buf, n, &n) > 0;
    if (ok) print_hex(label, buf, n);
    free(buf);
    return ok;
}

static int keygen(const char *alg) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, alg, NULL);
    EVP_PKEY *key = NULL;
    int rc = 1;
    if (ctx == NULL || EVP_PKEY_keygen_init(ctx) <= 0 || EVP_PKEY_generate(ctx, &key) <= 0) goto done;
    if (!export_component(key, OSSL_PKEY_PARAM_PUB_KEY, "public_key")) goto done;
    if (!export_component(key, OSSL_PKEY_PARAM_PRIV_KEY, "secret_key")) goto done;
    rc = 0;
done:
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(ctx);
    return rc;
}

static int kem_encaps(const char *alg, const char *pub_hex) {
    size_t pub_len = 0, ct_len = 0, ss_len = 0;
    unsigned char *pub = from_hex(pub_hex, &pub_len), *ct = NULL, *ss = NULL;
    EVP_PKEY *key = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    int rc = 1;
    if (pub == NULL || (key = import_key(alg, pub, pub_len, NULL, 0)) == NULL) goto done;
    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL);
    if (ctx == NULL || EVP_PKEY_encapsulate_init(ctx, NULL) <= 0) goto done;
    if (EVP_PKEY_encapsulate(ctx, NULL, &ct_len, NULL, &ss_len) <= 0) goto done;
    ct = malloc(ct_len); ss = malloc(ss_len);
    if (ct == NULL || ss == NULL || EVP_PKEY_encapsulate(ctx, ct, &ct_len, ss, &ss_len) <= 0) goto done;
    print_hex("ciphertext", ct, ct_len); print_hex("shared_secret", ss, ss_len); rc = 0;
done:
    free(pub); free(ct); free(ss); EVP_PKEY_CTX_free(ctx); EVP_PKEY_free(key); return rc;
}

static int kem_decaps(const char *alg, const char *priv_hex, const char *ct_hex, const char *pub_hex) {
    size_t priv_len = 0, ct_len = 0, pub_len = 0, ss_len = 0;
    unsigned char *priv = from_hex(priv_hex, &priv_len), *ct = from_hex(ct_hex, &ct_len);
    unsigned char *pub = pub_hex != NULL && pub_hex[0] != '\0' ? from_hex(pub_hex, &pub_len) : NULL;
    unsigned char *ss = NULL;
    EVP_PKEY *key = NULL; EVP_PKEY_CTX *ctx = NULL; int rc = 1;
    if (priv == NULL || ct == NULL || (key = import_key(alg, pub, pub_len, priv, priv_len)) == NULL) goto done;
    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL);
    if (ctx == NULL || EVP_PKEY_decapsulate_init(ctx, NULL) <= 0) goto done;
    if (EVP_PKEY_decapsulate(ctx, NULL, &ss_len, ct, ct_len) <= 0) goto done;
    ss = malloc(ss_len);
    if (ss == NULL || EVP_PKEY_decapsulate(ctx, ss, &ss_len, ct, ct_len) <= 0) goto done;
    print_hex("shared_secret", ss, ss_len); rc = 0;
done:
    free(priv); free(ct); free(pub); free(ss); EVP_PKEY_CTX_free(ctx); EVP_PKEY_free(key); return rc;
}

static int dsa_sign(const char *alg, const char *priv_hex, const char *pub_hex,
                    const char *msg_hex, const char *ctx_hex) {
    size_t priv_len = 0, pub_len = 0, msg_len = 0, context_len = 0, sig_len = 0;
    unsigned char *priv = from_hex(priv_hex, &priv_len), *pub = from_hex(pub_hex, &pub_len);
    unsigned char *msg = from_hex(msg_hex, &msg_len), *context = from_hex(ctx_hex, &context_len), *sig = NULL;
    EVP_PKEY *key = NULL; EVP_PKEY_CTX *ctx = NULL; int rc = 1;
    if (priv == NULL || pub == NULL || msg == NULL || context == NULL ||
        (key = import_key(alg, pub, pub_len, priv, priv_len)) == NULL) goto done;
    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL);
    OSSL_PARAM params[2] = {
        OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING, context, context_len),
        OSSL_PARAM_construct_end()
    };
    if (ctx == NULL || EVP_PKEY_sign_message_init(ctx, NULL, params) <= 0) goto done;
    if (EVP_PKEY_sign(ctx, NULL, &sig_len, msg, msg_len) <= 0) goto done;
    sig = malloc(sig_len);
    if (sig == NULL || EVP_PKEY_sign(ctx, sig, &sig_len, msg, msg_len) <= 0) goto done;
    print_hex("signature", sig, sig_len); rc = 0;
done:
    free(priv); free(pub); free(msg); free(context); free(sig); EVP_PKEY_CTX_free(ctx); EVP_PKEY_free(key); return rc;
}

static int dsa_verify(const char *alg, const char *pub_hex, const char *msg_hex,
                      const char *ctx_hex, const char *sig_hex) {
    size_t pub_len = 0, msg_len = 0, context_len = 0, sig_len = 0;
    unsigned char *pub = from_hex(pub_hex, &pub_len), *msg = from_hex(msg_hex, &msg_len);
    unsigned char *context = from_hex(ctx_hex, &context_len), *sig = from_hex(sig_hex, &sig_len);
    EVP_PKEY *key = NULL; EVP_PKEY_CTX *ctx = NULL; int rc = 1;
    if (pub == NULL || msg == NULL || context == NULL || sig == NULL ||
        (key = import_key(alg, pub, pub_len, NULL, 0)) == NULL) goto done;
    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL);
    OSSL_PARAM params[2] = {
        OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING, context, context_len),
        OSSL_PARAM_construct_end()
    };
    if (ctx == NULL || EVP_PKEY_verify_message_init(ctx, NULL, params) <= 0) goto done;
    int valid = EVP_PKEY_verify(ctx, sig, sig_len, msg, msg_len);
    printf("valid=%s\n", valid == 1 ? "true" : "false"); rc = valid >= 0 ? 0 : 1;
done:
    free(pub); free(msg); free(context); free(sig); EVP_PKEY_CTX_free(ctx); EVP_PKEY_free(key); return rc;
}

int main(int argc, char **argv) {
    if (argc < 3) return 64;
    const char *op = argv[1], *alg = argv[2];
    if (strcmp(op, "version") == 0) { printf("version=%s\n", OpenSSL_version(OPENSSL_VERSION)); return 0; }
    if (strcmp(op, "kem-keygen") == 0 || strcmp(op, "dsa-keygen") == 0) return keygen(alg);
    if (strcmp(op, "kem-encaps") == 0 && argc >= 4) return kem_encaps(alg, argv[3]);
    if (strcmp(op, "kem-decaps") == 0 && argc >= 5) return kem_decaps(alg, argv[3], argv[4], argc >= 6 ? argv[5] : NULL);
    if (strcmp(op, "dsa-sign") == 0 && argc >= 7) return dsa_sign(alg, argv[3], argv[4], argv[5], argv[6]);
    if (strcmp(op, "dsa-verify") == 0 && argc >= 7) return dsa_verify(alg, argv[3], argv[4], argv[5], argv[6]);
    return 65;
}
