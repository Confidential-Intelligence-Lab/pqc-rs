#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>
#include <openssl/params.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned char *from_hex(
    const char *s,
    size_t *n
)
{
    size_t len;
    unsigned char *b;
    size_t i;

    if (s == NULL || n == NULL) {
        return NULL;
    }

    len = strlen(s);

    if ((len & 1U) != 0U) {
        return NULL;
    }

    *n = len / 2U;

    b = malloc(*n == 0U ? 1U : *n);

    if (b == NULL) {
        return NULL;
    }

    for (i = 0; i < *n; i++) {
        unsigned int x = 0;

        if (sscanf(
                s + (2U * i),
                "%2x",
                &x
            ) != 1) {
            free(b);
            return NULL;
        }

        b[i] = (unsigned char)x;
    }

    return b;
}

static void print_hex(
    const char *name,
    const unsigned char *b,
    size_t n
)
{
    size_t i;

    printf("%s=", name);

    for (i = 0; i < n; i++) {
        printf("%02x", b[i]);
    }

    putchar('\n');
}

static EVP_PKEY *import_key(
    const char *alg,
    unsigned char *pub,
    size_t pub_len,
    unsigned char *priv,
    size_t priv_len
)
{
    EVP_PKEY_CTX *ctx;
    EVP_PKEY *key = NULL;
    OSSL_PARAM params[3];
    size_t i = 0;
    int selection;

    ctx = EVP_PKEY_CTX_new_from_name(
        NULL,
        alg,
        NULL
    );

    if (ctx == NULL) {
        return NULL;
    }

    if (EVP_PKEY_fromdata_init(ctx) <= 0) {
        goto done;
    }

    if (pub != NULL) {
        params[i++] = OSSL_PARAM_construct_octet_string(
            OSSL_PKEY_PARAM_PUB_KEY,
            pub,
            pub_len
        );
    }

    if (priv != NULL) {
        params[i++] = OSSL_PARAM_construct_octet_string(
            OSSL_PKEY_PARAM_PRIV_KEY,
            priv,
            priv_len
        );
    }

    params[i] = OSSL_PARAM_construct_end();

    if (pub != NULL && priv != NULL) {
        selection = EVP_PKEY_KEYPAIR;
    }
    else if (priv != NULL) {
        selection = EVP_PKEY_PRIVATE_KEY;
    }
    else {
        selection = EVP_PKEY_PUBLIC_KEY;
    }

    if (EVP_PKEY_fromdata(
            ctx,
            &key,
            selection,
            params
        ) <= 0) {
        key = NULL;
    }

done:

    EVP_PKEY_CTX_free(ctx);
    return key;
}

static int export_component(
    EVP_PKEY *key,
    const char *name,
    const char *label
)
{
    size_t n = 0;
    unsigned char *buf;
    int ok;

    if (EVP_PKEY_get_octet_string_param(
            key,
            name,
            NULL,
            0,
            &n
        ) <= 0) {
        return 0;
    }

    buf = malloc(n == 0U ? 1U : n);

    if (buf == NULL) {
        return 0;
    }

    ok = EVP_PKEY_get_octet_string_param(
        key,
        name,
        buf,
        n,
        &n
    ) > 0;

    if (ok) {
        print_hex(label, buf, n);
    }

    free(buf);
    return ok;
}

static int deterministic_keygen(
    const char *alg,
    const char *seed_hex,
    const char *seed_param_name
)
{
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *key = NULL;

    unsigned char *seed = NULL;
    size_t seed_len = 0;

    OSSL_PARAM params[2];

    int rc = 1;

    seed = from_hex(
        seed_hex,
        &seed_len
    );

    if (seed == NULL) {
        fprintf(stderr, "invalid keygen seed\n");
        goto done;
    }

    ctx = EVP_PKEY_CTX_new_from_name(
        NULL,
        alg,
        NULL
    );

    if (ctx == NULL) {
        fprintf(stderr, "keygen context creation failed\n");
        goto done;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        fprintf(stderr, "keygen init failed\n");
        goto done;
    }

    params[0] = OSSL_PARAM_construct_octet_string(
        seed_param_name,
        seed,
        seed_len
    );

    params[1] = OSSL_PARAM_construct_end();

    if (EVP_PKEY_CTX_set_params(
            ctx,
            params
        ) <= 0) {
        fprintf(stderr, "keygen seed parameter failed\n");
        goto done;
    }

    if (EVP_PKEY_generate(
            ctx,
            &key
        ) <= 0) {
        fprintf(stderr, "key generation failed\n");
        goto done;
    }

    if (!export_component(
            key,
            OSSL_PKEY_PARAM_PUB_KEY,
            "public_key"
        )) {
        fprintf(stderr, "public key export failed\n");
        goto done;
    }

    if (!export_component(
            key,
            OSSL_PKEY_PARAM_PRIV_KEY,
            "secret_key"
        )) {
        fprintf(stderr, "secret key export failed\n");
        goto done;
    }

    rc = 0;

done:

    free(seed);
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(ctx);

    return rc;
}

static int kem_keygen(
    const char *alg,
    const char *d_hex,
    const char *z_hex
)
{
    size_t d_len = 0;
    size_t z_len = 0;

    unsigned char *d = NULL;
    unsigned char *z = NULL;

    unsigned char seed[64];

    char seed_hex[129];

    int rc = 1;

    d = from_hex(d_hex, &d_len);
    z = from_hex(z_hex, &z_len);

    if (
        d == NULL ||
        z == NULL ||
        d_len != 32U ||
        z_len != 32U
    ) {
        fprintf(
            stderr,
            "d and z must each be 32 bytes\n"
        );
        goto done;
    }

    memcpy(seed, d, 32U);
    memcpy(seed + 32U, z, 32U);

    {
        size_t i;

        for (i = 0; i < sizeof(seed); i++) {
            sprintf(
                seed_hex + (2U * i),
                "%02x",
                seed[i]
            );
        }

        seed_hex[128] = '\0';
    }

    rc = deterministic_keygen(
        alg,
        seed_hex,
        OSSL_PKEY_PARAM_ML_KEM_SEED
    );

done:

    free(d);
    free(z);

    return rc;
}

static int dsa_keygen(
    const char *alg,
    const char *xi_hex
)
{
    size_t xi_len = 0;
    unsigned char *xi = NULL;
    int rc;

    xi = from_hex(xi_hex, &xi_len);

    if (xi == NULL || xi_len != 32U) {
        free(xi);
        fprintf(stderr, "xi must be 32 bytes\n");
        return 1;
    }

    free(xi);

    rc = deterministic_keygen(
        alg,
        xi_hex,
        OSSL_PKEY_PARAM_ML_DSA_SEED
    );

    return rc;
}

static int kem_encaps(
    const char *alg,
    const char *pub_hex,
    const char *m_hex
)
{
    size_t pub_len = 0;
    size_t m_len = 0;
    size_t ct_len = 0;
    size_t ss_len = 0;

    unsigned char *pub = NULL;
    unsigned char *m = NULL;
    unsigned char *ct = NULL;
    unsigned char *ss = NULL;

    EVP_PKEY *key = NULL;
    EVP_PKEY_CTX *ctx = NULL;

    OSSL_PARAM params[2];

    int rc = 1;

    pub = from_hex(pub_hex, &pub_len);
    m = from_hex(m_hex, &m_len);

    if (
        pub == NULL ||
        m == NULL ||
        m_len != 32U
    ) {
        fprintf(stderr, "invalid encapsulation input\n");
        goto done;
    }

    key = import_key(
        alg,
        pub,
        pub_len,
        NULL,
        0
    );

    if (key == NULL) {
        fprintf(stderr, "public key import failed\n");
        goto done;
    }

    ctx = EVP_PKEY_CTX_new_from_pkey(
        NULL,
        key,
        NULL
    );

    if (ctx == NULL) {
        goto done;
    }

    params[0] = OSSL_PARAM_construct_octet_string(
        OSSL_KEM_PARAM_IKME,
        m,
        m_len
    );

    params[1] = OSSL_PARAM_construct_end();

    if (EVP_PKEY_encapsulate_init(
            ctx,
            params
        ) <= 0) {
        fprintf(stderr, "encapsulate init failed\n");
        goto done;
    }

    if (EVP_PKEY_encapsulate(
            ctx,
            NULL,
            &ct_len,
            NULL,
            &ss_len
        ) <= 0) {
        goto done;
    }

    ct = malloc(ct_len);
    ss = malloc(ss_len);

    if (ct == NULL || ss == NULL) {
        goto done;
    }

    if (EVP_PKEY_encapsulate(
            ctx,
            ct,
            &ct_len,
            ss,
            &ss_len
        ) <= 0) {
        fprintf(stderr, "encapsulation failed\n");
        goto done;
    }

    print_hex(
        "ciphertext",
        ct,
        ct_len
    );

    print_hex(
        "shared_secret",
        ss,
        ss_len
    );

    rc = 0;

done:

    free(pub);
    free(m);
    free(ct);
    free(ss);

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(key);

    return rc;
}

static int kem_decaps(
    const char *alg,
    const char *priv_hex,
    const char *ct_hex
)
{
    size_t priv_len = 0;
    size_t ct_len = 0;
    size_t ss_len = 0;

    unsigned char *priv = NULL;
    unsigned char *ct = NULL;
    unsigned char *ss = NULL;

    EVP_PKEY *key = NULL;
    EVP_PKEY_CTX *ctx = NULL;

    int rc = 1;

    priv = from_hex(priv_hex, &priv_len);
    ct = from_hex(ct_hex, &ct_len);

    if (priv == NULL || ct == NULL) {
        goto done;
    }

    key = import_key(
        alg,
        NULL,
        0,
        priv,
        priv_len
    );

    if (key == NULL) {
        fprintf(stderr, "private key import failed\n");
        goto done;
    }

    ctx = EVP_PKEY_CTX_new_from_pkey(
        NULL,
        key,
        NULL
    );

    if (
        ctx == NULL ||
        EVP_PKEY_decapsulate_init(
            ctx,
            NULL
        ) <= 0
    ) {
        goto done;
    }

    if (EVP_PKEY_decapsulate(
            ctx,
            NULL,
            &ss_len,
            ct,
            ct_len
        ) <= 0) {
        goto done;
    }

    ss = malloc(ss_len);

    if (
        ss == NULL ||
        EVP_PKEY_decapsulate(
            ctx,
            ss,
            &ss_len,
            ct,
            ct_len
        ) <= 0
    ) {
        goto done;
    }

    print_hex(
        "shared_secret",
        ss,
        ss_len
    );

    rc = 0;

done:

    free(priv);
    free(ct);
    free(ss);

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(key);

    return rc;
}

static int dsa_sign(
    const char *alg,
    const char *priv_hex,
    const char *msg_hex,
    const char *ctx_hex,
    const char *rnd_hex
)
{
    size_t priv_len = 0;
    size_t msg_len = 0;
    size_t context_len = 0;
    size_t rnd_len = 0;
    size_t sig_len = 0;

    unsigned char *priv = NULL;
    unsigned char *msg = NULL;
    unsigned char *context = NULL;
    unsigned char *rnd = NULL;
    unsigned char *sig = NULL;

    EVP_PKEY *key = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_SIGNATURE *signature_alg = NULL;

    OSSL_PARAM params[3];

    int rc = 1;

    priv = from_hex(priv_hex, &priv_len);
    msg = from_hex(msg_hex, &msg_len);
    context = from_hex(ctx_hex, &context_len);
    rnd = from_hex(rnd_hex, &rnd_len);

    if (
        priv == NULL ||
        msg == NULL ||
        context == NULL ||
        rnd == NULL ||
        rnd_len != 32U ||
        context_len > 255U
    ) {
        fprintf(stderr, "invalid signing input\n");
        goto done;
    }

    key = import_key(
        alg,
        NULL,
        0,
        priv,
        priv_len
    );

    if (key == NULL) {
        fprintf(stderr, "private key import failed\n");
        goto done;
    }

    ctx = EVP_PKEY_CTX_new_from_pkey(
        NULL,
        key,
        NULL
    );

    signature_alg = EVP_SIGNATURE_fetch(
        NULL,
        alg,
        NULL
    );

    if (ctx == NULL || signature_alg == NULL) {
        goto done;
    }

    params[0] = OSSL_PARAM_construct_octet_string(
        OSSL_SIGNATURE_PARAM_CONTEXT_STRING,
        context,
        context_len
    );

    params[1] = OSSL_PARAM_construct_octet_string(
        OSSL_SIGNATURE_PARAM_TEST_ENTROPY,
        rnd,
        rnd_len
    );

    params[2] = OSSL_PARAM_construct_end();

    if (EVP_PKEY_sign_message_init(
            ctx,
            signature_alg,
            params
        ) <= 0) {
        fprintf(stderr, "ML-DSA sign init failed\n");
        goto done;
    }

    if (EVP_PKEY_sign(
            ctx,
            NULL,
            &sig_len,
            msg,
            msg_len
        ) <= 0) {
        goto done;
    }

    sig = malloc(sig_len);

    if (
        sig == NULL ||
        EVP_PKEY_sign(
            ctx,
            sig,
            &sig_len,
            msg,
            msg_len
        ) <= 0
    ) {
        fprintf(stderr, "ML-DSA signing failed\n");
        goto done;
    }

    print_hex(
        "signature",
        sig,
        sig_len
    );

    rc = 0;

done:

    free(priv);
    free(msg);
    free(context);
    free(rnd);
    free(sig);

    EVP_SIGNATURE_free(signature_alg);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(key);

    return rc;
}

static int dsa_verify(
    const char *alg,
    const char *pub_hex,
    const char *msg_hex,
    const char *ctx_hex,
    const char *sig_hex
)
{
    size_t pub_len = 0;
    size_t msg_len = 0;
    size_t context_len = 0;
    size_t sig_len = 0;

    unsigned char *pub = NULL;
    unsigned char *msg = NULL;
    unsigned char *context = NULL;
    unsigned char *sig = NULL;

    EVP_PKEY *key = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_SIGNATURE *signature_alg = NULL;

    OSSL_PARAM params[2];

    int valid;
    int rc = 1;

    pub = from_hex(pub_hex, &pub_len);
    msg = from_hex(msg_hex, &msg_len);
    context = from_hex(ctx_hex, &context_len);
    sig = from_hex(sig_hex, &sig_len);

    if (
        pub == NULL ||
        msg == NULL ||
        context == NULL ||
        sig == NULL ||
        context_len > 255U
    ) {
        goto done;
    }

    key = import_key(
        alg,
        pub,
        pub_len,
        NULL,
        0
    );

    if (key == NULL) {
        goto done;
    }

    ctx = EVP_PKEY_CTX_new_from_pkey(
        NULL,
        key,
        NULL
    );

    signature_alg = EVP_SIGNATURE_fetch(
        NULL,
        alg,
        NULL
    );

    if (ctx == NULL || signature_alg == NULL) {
        goto done;
    }

    params[0] = OSSL_PARAM_construct_octet_string(
        OSSL_SIGNATURE_PARAM_CONTEXT_STRING,
        context,
        context_len
    );

    params[1] = OSSL_PARAM_construct_end();

    if (EVP_PKEY_verify_message_init(
            ctx,
            signature_alg,
            params
        ) <= 0) {
        goto done;
    }

    valid = EVP_PKEY_verify(
        ctx,
        sig,
        sig_len,
        msg,
        msg_len
    );

    printf(
        "valid=%s\n",
        valid == 1 ? "true" : "false"
    );

    rc = valid >= 0 ? 0 : 1;

done:

    free(pub);
    free(msg);
    free(context);
    free(sig);

    EVP_SIGNATURE_free(signature_alg);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(key);

    return rc;
}

int main(
    int argc,
    char **argv
)
{
    const char *op;
    const char *alg;

    if (argc < 3) {
        return 64;
    }

    op = argv[1];
    alg = argv[2];

    if (strcmp(op, "version") == 0) {
        printf(
            "version=%s\n",
            OpenSSL_version(OPENSSL_VERSION)
        );

        return 0;
    }

    if (
        strcmp(op, "kem-keygen") == 0 &&
        argc == 5
    ) {
        return kem_keygen(
            alg,
            argv[3],
            argv[4]
        );
    }

    if (
        strcmp(op, "kem-encaps") == 0 &&
        argc == 5
    ) {
        return kem_encaps(
            alg,
            argv[3],
            argv[4]
        );
    }

    if (
        strcmp(op, "kem-decaps") == 0 &&
        argc == 5
    ) {
        return kem_decaps(
            alg,
            argv[3],
            argv[4]
        );
    }

    if (
        strcmp(op, "dsa-keygen") == 0 &&
        argc == 4
    ) {
        return dsa_keygen(
            alg,
            argv[3]
        );
    }

    if (
        strcmp(op, "dsa-sign") == 0 &&
        argc == 7
    ) {
        return dsa_sign(
            alg,
            argv[3],
            argv[4],
            argv[5],
            argv[6]
        );
    }

    if (
        strcmp(op, "dsa-verify") == 0 &&
        argc == 7
    ) {
        return dsa_verify(
            alg,
            argv[3],
            argv[4],
            argv[5],
            argv[6]
        );
    }

    return 65;
}
