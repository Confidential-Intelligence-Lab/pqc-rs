#include <oqs/oqs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned char *from_hex(const char *s, size_t *n){size_t len=strlen(s);if(len%2)return NULL;*n=len/2;unsigned char *b=malloc(*n?*n:1);for(size_t i=0;i<*n;i++){unsigned x;if(sscanf(s+2*i,"%2x",&x)!=1){free(b);return NULL;}b[i]=(unsigned char)x;}return b;}
static void print_hex(const char *k,const unsigned char *b,size_t n){printf("%s=",k);for(size_t i=0;i<n;i++)printf("%02x",b[i]);printf("\n");}
static int kem(const char *op,const char *alg,int argc,char **argv){OQS_KEM *k=OQS_KEM_new(alg);if(!k)return 2;int rc=1;
 if(!strcmp(op,"kem-keygen")){unsigned char *pk=malloc(k->length_public_key),*sk=malloc(k->length_secret_key);if(OQS_KEM_keypair(k,pk,sk)==OQS_SUCCESS){print_hex("public_key",pk,k->length_public_key);print_hex("secret_key",sk,k->length_secret_key);rc=0;}free(pk);free(sk);}
 else if(!strcmp(op,"kem-encaps")&&argc>=4){size_t pn;unsigned char *pk=from_hex(argv[3],&pn),*ct=malloc(k->length_ciphertext),*ss=malloc(k->length_shared_secret);if(pk&&pn==k->length_public_key&&OQS_KEM_encaps(k,ct,ss,pk)==OQS_SUCCESS){print_hex("ciphertext",ct,k->length_ciphertext);print_hex("shared_secret",ss,k->length_shared_secret);rc=0;}free(pk);free(ct);free(ss);}
 else if(!strcmp(op,"kem-decaps")&&argc>=5){size_t sn,cn;unsigned char *sk=from_hex(argv[3],&sn),*ct=from_hex(argv[4],&cn),*ss=malloc(k->length_shared_secret);if(sk&&ct&&sn==k->length_secret_key&&cn==k->length_ciphertext&&OQS_KEM_decaps(k,ss,ct,sk)==OQS_SUCCESS){print_hex("shared_secret",ss,k->length_shared_secret);rc=0;}free(sk);free(ct);free(ss);}
 OQS_KEM_free(k);return rc;}
static const char *sig_alg_name(const char *alg) {
    if (!strcmp(alg, "SLH-DSA-SHA2-128s")) return OQS_SIG_alg_slh_dsa_pure_sha2_128s;
    if (!strcmp(alg, "SLH-DSA-SHA2-128f")) return OQS_SIG_alg_slh_dsa_pure_sha2_128f;
    if (!strcmp(alg, "SLH-DSA-SHA2-192s")) return OQS_SIG_alg_slh_dsa_pure_sha2_192s;
    if (!strcmp(alg, "SLH-DSA-SHA2-192f")) return OQS_SIG_alg_slh_dsa_pure_sha2_192f;
    if (!strcmp(alg, "SLH-DSA-SHA2-256s")) return OQS_SIG_alg_slh_dsa_pure_sha2_256s;
    if (!strcmp(alg, "SLH-DSA-SHA2-256f")) return OQS_SIG_alg_slh_dsa_pure_sha2_256f;
    if (!strcmp(alg, "SLH-DSA-SHAKE-128s")) return OQS_SIG_alg_slh_dsa_pure_shake_128s;
    if (!strcmp(alg, "SLH-DSA-SHAKE-128f")) return OQS_SIG_alg_slh_dsa_pure_shake_128f;
    if (!strcmp(alg, "SLH-DSA-SHAKE-192s")) return OQS_SIG_alg_slh_dsa_pure_shake_192s;
    if (!strcmp(alg, "SLH-DSA-SHAKE-192f")) return OQS_SIG_alg_slh_dsa_pure_shake_192f;
    if (!strcmp(alg, "SLH-DSA-SHAKE-256s")) return OQS_SIG_alg_slh_dsa_pure_shake_256s;
    if (!strcmp(alg, "SLH-DSA-SHAKE-256f")) return OQS_SIG_alg_slh_dsa_pure_shake_256f;
    return alg;
}

static const char *hash_sig_alg_name(const char *alg, const char *prehash) {
    const char *family = NULL;
    const char *level = NULL;
    const char *speed = NULL;
    const char *ph = NULL;

    if (!strncmp(alg, "SLH-DSA-SHA2-", 13)) {
        family = "SHA2";
    } else if (!strncmp(alg, "SLH-DSA-SHAKE-", 14)) {
        family = "SHAKE";
    } else {
        return NULL;
    }

    const char *suffix = strrchr(alg, '-');
    if (!suffix || strlen(suffix + 1) < 4) return NULL;

    if (!strncmp(suffix + 1, "128", 3)) level = "128";
    else if (!strncmp(suffix + 1, "192", 3)) level = "192";
    else if (!strncmp(suffix + 1, "256", 3)) level = "256";
    else return NULL;

    speed = suffix[strlen(suffix) - 1] == 's' ? "S" :
            suffix[strlen(suffix) - 1] == 'f' ? "F" : NULL;
    if (!speed) return NULL;

    if (!strcmp(prehash, "SHA2-224")) ph = "SHA2_224";
    else if (!strcmp(prehash, "SHA2-256")) ph = "SHA2_256";
    else if (!strcmp(prehash, "SHA2-384")) ph = "SHA2_384";
    else if (!strcmp(prehash, "SHA2-512")) ph = "SHA2_512";
    else if (!strcmp(prehash, "SHA2-512/224")) ph = "SHA2_512_224";
    else if (!strcmp(prehash, "SHA2-512/256")) ph = "SHA2_512_256";
    else if (!strcmp(prehash, "SHA3-224")) ph = "SHA3_224";
    else if (!strcmp(prehash, "SHA3-256")) ph = "SHA3_256";
    else if (!strcmp(prehash, "SHA3-384")) ph = "SHA3_384";
    else if (!strcmp(prehash, "SHA3-512")) ph = "SHA3_512";
    else if (!strcmp(prehash, "SHAKE-128")) ph = "SHAKE_128";
    else if (!strcmp(prehash, "SHAKE-256")) ph = "SHAKE_256";
    else return NULL;

    static char name[96];
    snprintf(
        name,
        sizeof(name),
        "SLH_DSA_%s_PREHASH_%s_%s%s",
        ph,
        family,
        level,
        speed
    );
    return name;
}

static int sig(const char *op,const char *alg,int argc,char **argv){const char *selected_alg=sig_alg_name(alg);if(!strcmp(op,"slh-hash-sign")&&argc>=7)selected_alg=hash_sig_alg_name(alg,argv[6]);else if(!strcmp(op,"slh-hash-verify")&&argc>=8)selected_alg=hash_sig_alg_name(alg,argv[7]);if(!selected_alg)return 2;OQS_SIG *s=OQS_SIG_new(selected_alg);if(!s)return 2;int rc=1;
 if(!strcmp(op,"dsa-keygen")||!strcmp(op,"slh-keygen")){unsigned char *pk=malloc(s->length_public_key),*sk=malloc(s->length_secret_key);if(OQS_SIG_keypair(s,pk,sk)==OQS_SUCCESS){print_hex("public_key",pk,s->length_public_key);print_hex("secret_key",sk,s->length_secret_key);rc=0;}free(pk);free(sk);}
 else if((!strcmp(op,"dsa-sign")||!strcmp(op,"slh-sign")||!strcmp(op,"slh-hash-sign"))&&argc>=6){size_t sn,mn,cn;unsigned char *sk=from_hex(argv[3],&sn),*m=from_hex(argv[4],&mn),*ctx=from_hex(argv[5],&cn),*out=malloc(s->length_signature);size_t outn=0;if(sk&&m&&ctx&&sn==s->length_secret_key&&OQS_SIG_sign_with_ctx_str(s,out,&outn,m,mn,ctx,cn,sk)==OQS_SUCCESS){print_hex("signature",out,outn);rc=0;}free(sk);free(m);free(ctx);free(out);}
 else if((!strcmp(op,"dsa-verify")||!strcmp(op,"slh-verify")||!strcmp(op,"slh-hash-verify"))&&argc>=7){size_t pn,mn,cn,gn;unsigned char *pk=from_hex(argv[3],&pn),*m=from_hex(argv[4],&mn),*ctx=from_hex(argv[5],&cn),*g=from_hex(argv[6],&gn);if(pk&&m&&ctx&&g&&pn==s->length_public_key){printf("valid=%s\n",OQS_SIG_verify_with_ctx_str(s,m,mn,g,gn,ctx,cn,pk)==OQS_SUCCESS?"true":"false");rc=0;}free(pk);free(m);free(ctx);free(g);}
 OQS_SIG_free(s);return rc;}
int main(int argc,char **argv){if(argc<3)return 64;if(!strncmp(argv[2],"ML-KEM",6))return kem(argv[1],argv[2],argc,argv);if(!strncmp(argv[2],"ML-DSA",6)||!strncmp(argv[2],"SLH-DSA",7))return sig(argv[1],argv[2],argc,argv);return 65;}
