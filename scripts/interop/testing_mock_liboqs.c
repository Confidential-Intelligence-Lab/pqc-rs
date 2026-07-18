#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef int OQS_STATUS;
#define OQS_SUCCESS 0
#define OQS_ERROR 1

typedef struct OQS_KEM {
    const char *method_name;
    const char *alg_version;
    uint8_t claimed_nist_level;
    bool ind_cca;
    size_t length_public_key;
    size_t length_secret_key;
    size_t length_ciphertext;
    size_t length_shared_secret;
    size_t length_keypair_seed;
    size_t length_encaps_seed;
    void *keypair_derand;
    void *keypair;
    void *encaps_derand;
    void *encaps;
    void *decaps;
} OQS_KEM;

typedef struct OQS_SIG {
    const char *method_name;
    const char *alg_version;
    uint8_t claimed_nist_level;
    bool euf_cma;
    bool suf_cma;
    bool sig_with_ctx_support;
    size_t length_public_key;
    size_t length_secret_key;
    size_t length_signature;
    void *keypair;
    void *sign;
    void *sign_with_ctx_str;
    void *verify;
    void *verify_with_ctx_str;
} OQS_SIG;

void OQS_init(void) {}
void OQS_destroy(void) {}
const char *OQS_version(void) { return "a2.2-mock"; }

static bool kem_lengths(const char *name, size_t *pk, size_t *sk, size_t *ct) {
    if (!strcmp(name, "ML-KEM-512")) { *pk=800; *sk=1632; *ct=768; return true; }
    if (!strcmp(name, "ML-KEM-768")) { *pk=1184; *sk=2400; *ct=1088; return true; }
    if (!strcmp(name, "ML-KEM-1024")) { *pk=1568; *sk=3168; *ct=1568; return true; }
    return false;
}
int OQS_KEM_alg_is_enabled(const char *name) { size_t a,b,c; return kem_lengths(name,&a,&b,&c); }
OQS_KEM *OQS_KEM_new(const char *name) {
    size_t pk,sk,ct; if (!kem_lengths(name,&pk,&sk,&ct)) return NULL;
    OQS_KEM *k=calloc(1,sizeof(*k)); k->method_name=name; k->alg_version="mock"; k->claimed_nist_level=1;
    k->ind_cca=true; k->length_public_key=pk; k->length_secret_key=sk; k->length_ciphertext=ct;
    k->length_shared_secret=32; k->length_keypair_seed=64; k->length_encaps_seed=32; return k;
}
void OQS_KEM_free(OQS_KEM *k) { free(k); }
OQS_STATUS OQS_KEM_keypair(const OQS_KEM *k, uint8_t *pk, uint8_t *sk) { memset(pk,0x11,k->length_public_key); memset(sk,0x22,k->length_secret_key); return 0; }
OQS_STATUS OQS_KEM_keypair_derand(const OQS_KEM *k, uint8_t *pk, uint8_t *sk, const uint8_t *seed) { (void)seed; return OQS_KEM_keypair(k,pk,sk); }
OQS_STATUS OQS_KEM_encaps(const OQS_KEM *k, uint8_t *ct, uint8_t *ss, const uint8_t *pk) { (void)pk; memset(ct,0x33,k->length_ciphertext); memset(ss,0x44,k->length_shared_secret); return 0; }
OQS_STATUS OQS_KEM_encaps_derand(const OQS_KEM *k, uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *seed) { (void)seed; return OQS_KEM_encaps(k,ct,ss,pk); }
OQS_STATUS OQS_KEM_decaps(const OQS_KEM *k, uint8_t *ss, const uint8_t *ct, const uint8_t *sk) { (void)ct; (void)sk; memset(ss,0x44,k->length_shared_secret); return 0; }

static bool sig_lengths(const char *name, size_t *pk, size_t *sk, size_t *sg) {
    if (!strcmp(name, "ML-DSA-44")) { *pk=1312; *sk=2560; *sg=2420; return true; }
    if (!strcmp(name, "ML-DSA-65")) { *pk=1952; *sk=4032; *sg=3309; return true; }
    if (!strcmp(name, "ML-DSA-87")) { *pk=2592; *sk=4896; *sg=4627; return true; }
    return false;
}
int OQS_SIG_alg_is_enabled(const char *name) { size_t a,b,c; return sig_lengths(name,&a,&b,&c); }
OQS_SIG *OQS_SIG_new(const char *name) {
    size_t pk,sk,sg; if (!sig_lengths(name,&pk,&sk,&sg)) return NULL;
    OQS_SIG *s=calloc(1,sizeof(*s)); s->method_name=name; s->alg_version="mock"; s->claimed_nist_level=1;
    s->euf_cma=true; s->suf_cma=false; s->sig_with_ctx_support=true;
    s->length_public_key=pk; s->length_secret_key=sk; s->length_signature=sg; return s;
}
void OQS_SIG_free(OQS_SIG *s) { free(s); }
OQS_STATUS OQS_SIG_keypair(const OQS_SIG *s, uint8_t *pk, uint8_t *sk) { memset(pk,0x55,s->length_public_key); memset(sk,0x66,s->length_secret_key); return 0; }
OQS_STATUS OQS_SIG_sign(const OQS_SIG *s, uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk) { (void)m;(void)mlen;(void)sk; memset(sig,0x77,s->length_signature); *siglen=s->length_signature; return 0; }
OQS_STATUS OQS_SIG_sign_with_ctx_str(const OQS_SIG *s, uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *ctx, size_t ctxlen, const uint8_t *sk) { (void)ctx;(void)ctxlen; return OQS_SIG_sign(s,sig,siglen,m,mlen,sk); }
OQS_STATUS OQS_SIG_verify(const OQS_SIG *s, const uint8_t *m, size_t mlen, const uint8_t *sig, size_t siglen, const uint8_t *pk) { (void)m;(void)mlen;(void)sig;(void)pk; return siglen==s->length_signature ? 0 : 1; }
OQS_STATUS OQS_SIG_verify_with_ctx_str(const OQS_SIG *s, const uint8_t *m, size_t mlen, const uint8_t *sig, size_t siglen, const uint8_t *ctx, size_t ctxlen, const uint8_t *pk) { (void)ctx;(void)ctxlen; return OQS_SIG_verify(s,m,mlen,sig,siglen,pk); }
