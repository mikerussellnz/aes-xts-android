#ifndef __XTSLIB_H__
#define __XTSLIB_H__

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

typedef enum {AES_128, AES_256} AES_MODE;

typedef struct {
	EVP_CIPHER_CTX enc_ctx;
	EVP_CIPHER_CTX dec_ctx;
}CIPHER_CONTEXT;

void xts_init_library();
CIPHER_CONTEXT *xts_new_cipher_context(AES_MODE mode, unsigned char *key);
int xts_encrypt_buffer(CIPHER_CONTEXT *ctx, unsigned char *plaintext, unsigned char* ciphertext, int length, long long currentSector);
int xts_decrypt_buffer(CIPHER_CONTEXT *ctx, unsigned char *ciphertext, unsigned char* plaintext, int length, long long currentSector);
void xts_free_cipher_context(CIPHER_CONTEXT *ctx);

#endif
