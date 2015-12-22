#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include "xtslib.h"

void init_tweak_with_sector_value(unsigned char *tweak, long long sector) {
	tweak[7] = (unsigned char) ((sector >> 56) & 255);
	tweak[6] = (unsigned char) ((sector >> 48) & 255);
	tweak[5] = (unsigned char) ((sector >> 40) & 255);
	tweak[4] = (unsigned char) ((sector >> 32) & 255);
	tweak[3] = (unsigned char) ((sector >> 24) & 255);
	tweak[2] = (unsigned char) ((sector >> 16) & 255);
	tweak[1] = (unsigned char) ((sector >> 8) & 255);
	tweak[0] = (unsigned char) (sector & 255);
}

void xts_init_library() {
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
}

CIPHER_CONTEXT *xts_new_cipher_context(AES_MODE mode, unsigned char *key) {
	CIPHER_CONTEXT *ctx = calloc(sizeof(CIPHER_CONTEXT), 1);
	EVP_CIPHER_CTX_init(&ctx->enc_ctx);
	EVP_CIPHER_CTX_init(&ctx->dec_ctx);
	if (mode == AES_128) {
		EVP_EncryptInit_ex(&ctx->enc_ctx, EVP_aes_128_xts(), NULL, key, NULL);
		EVP_DecryptInit_ex(&ctx->dec_ctx, EVP_aes_128_xts(), NULL, key, NULL);
	} else {
		EVP_EncryptInit_ex(&ctx->enc_ctx, EVP_aes_256_xts(), NULL, key, NULL);
		EVP_DecryptInit_ex(&ctx->dec_ctx, EVP_aes_256_xts(), NULL, key, NULL);
	}
	EVP_CIPHER_CTX_set_padding(&ctx->enc_ctx, 0);
	EVP_CIPHER_CTX_set_padding(&ctx->dec_ctx, 0);
	return ctx;	
}

int xts_encrypt_buffer(CIPHER_CONTEXT *ctx, unsigned char *plaintext, unsigned char* ciphertext, int length, long long currentSector) {
	unsigned char tweak[16]  = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
	int outlen;
	init_tweak_with_sector_value(tweak, currentSector);
	EVP_EncryptInit_ex(&ctx->enc_ctx, NULL, NULL, NULL, tweak);
	EVP_EncryptUpdate(&ctx->enc_ctx, ciphertext, &outlen, plaintext, length);
	return outlen;
}

int xts_decrypt_buffer(CIPHER_CONTEXT *ctx, unsigned char *ciphertext, unsigned char* plaintext, int length, long long currentSector) {
	unsigned char tweak[16]  = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
	int outlen;
	init_tweak_with_sector_value(tweak, currentSector);
	EVP_DecryptInit_ex(&ctx->dec_ctx, NULL, NULL, NULL, tweak);
	EVP_DecryptUpdate(&ctx->dec_ctx, plaintext, &outlen, ciphertext, length);
	return outlen;
}

void xts_free_cipher_context(CIPHER_CONTEXT *ctx) {
	EVP_CIPHER_CTX_cleanup(&ctx->enc_ctx);
	EVP_CIPHER_CTX_cleanup(&ctx->dec_ctx);
	free(ctx);
}

