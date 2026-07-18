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
static int sig(const char *op,const char *alg,int argc,char **argv){OQS_SIG *s=OQS_SIG_new(alg);if(!s)return 2;int rc=1;
 if(!strcmp(op,"dsa-keygen")){unsigned char *pk=malloc(s->length_public_key),*sk=malloc(s->length_secret_key);if(OQS_SIG_keypair(s,pk,sk)==OQS_SUCCESS){print_hex("public_key",pk,s->length_public_key);print_hex("secret_key",sk,s->length_secret_key);rc=0;}free(pk);free(sk);}
 else if(!strcmp(op,"dsa-sign")&&argc>=6){size_t sn,mn,cn;unsigned char *sk=from_hex(argv[3],&sn),*m=from_hex(argv[4],&mn),*ctx=from_hex(argv[5],&cn),*out=malloc(s->length_signature);size_t outn=0;if(sk&&m&&ctx&&sn==s->length_secret_key&&OQS_SIG_sign_with_ctx_str(s,out,&outn,m,mn,ctx,cn,sk)==OQS_SUCCESS){print_hex("signature",out,outn);rc=0;}free(sk);free(m);free(ctx);free(out);}
 else if(!strcmp(op,"dsa-verify")&&argc>=7){size_t pn,mn,cn,gn;unsigned char *pk=from_hex(argv[3],&pn),*m=from_hex(argv[4],&mn),*ctx=from_hex(argv[5],&cn),*g=from_hex(argv[6],&gn);if(pk&&m&&ctx&&g&&pn==s->length_public_key){printf("valid=%s\n",OQS_SIG_verify_with_ctx_str(s,m,mn,g,gn,ctx,cn,pk)==OQS_SUCCESS?"true":"false");rc=0;}free(pk);free(m);free(ctx);free(g);}
 OQS_SIG_free(s);return rc;}
int main(int argc,char **argv){if(argc<3)return 64;if(!strncmp(argv[2],"ML-KEM",6))return kem(argv[1],argv[2],argc,argv);if(!strncmp(argv[2],"ML-DSA",6))return sig(argv[1],argv[2],argc,argv);return 65;}
