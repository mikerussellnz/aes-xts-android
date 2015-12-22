#include <jni.h>
#include "xtslib.h"

#ifdef __ANDROID__
#include <android/log.h>
#define printf(...) __android_log_print(ANDROID_LOG_DEBUG, "XTS-ENC", __VA_ARGS__);
#endif

void Java_com_mikerussell_filebrowser_encryption_JniOpenSSLCipher_init_1library(JNIEnv* env, jobject thiz) {
	xts_init_library();
}

jlong Java_com_mikerussell_filebrowser_encryption_JniOpenSSLCipher_new_1cipher_1context(
	JNIEnv* env, 
	jobject thiz, 
	jint mode, 
	jbyteArray key) {

	jbyte* keybytes = (*env)->GetPrimitiveArrayCritical(env, key, NULL);
	
	CIPHER_CONTEXT *ctx = xts_new_cipher_context((AES_MODE)mode, keybytes);

	(*env)->ReleasePrimitiveArrayCritical(env, key, keybytes, 0);
	
	return (jlong)(intptr_t)ctx;	
}

void Java_com_mikerussell_filebrowser_encryption_JniOpenSSLCipher_free_1cipher_1context(
	JNIEnv* env,
	jobject thiz,
	jlong ctx_ptr) {
	
	CIPHER_CONTEXT *ctx = (CIPHER_CONTEXT *) (intptr_t)ctx_ptr;
	xts_free_cipher_context(ctx);
}

jint Java_com_mikerussell_filebrowser_encryption_JniOpenSSLCipher_decrypt_1buffer(
	JNIEnv* env, 
	jobject thiz, 
	jlong ctx_ptr,
	jbyteArray ciphertext, 
	jbyteArray plaintext, 
	jint length, 
	jlong currentSector) {

	int i;
	CIPHER_CONTEXT *ctx = (CIPHER_CONTEXT *) (intptr_t)ctx_ptr;

	jbyte* cipherTextBytes = (*env)->GetPrimitiveArrayCritical(env, ciphertext, NULL);
	jbyte* plainTextBytes = (*env)->GetPrimitiveArrayCritical(env, plaintext, NULL);

	int result = xts_decrypt_buffer(ctx, cipherTextBytes, plainTextBytes, length, currentSector);

	(*env)->ReleasePrimitiveArrayCritical(env, ciphertext, cipherTextBytes, JNI_ABORT);
	(*env)->ReleasePrimitiveArrayCritical(env, plaintext, plainTextBytes, 0);

	return result;
}

jint Java_com_mikerussell_filebrowser_encryption_JniOpenSSLCipher_encrypt_1buffer(
	JNIEnv* env, 
	jobject thiz,
	jlong ctx_ptr, 
        jbyteArray plaintext, 
	jbyteArray ciphertext, 
	jint length, 
	jlong currentSector) {

	int i;
	CIPHER_CONTEXT *ctx = (CIPHER_CONTEXT *) (intptr_t)ctx_ptr;

	jbyte* plainTextBytes = (*env)->GetPrimitiveArrayCritical(env, plaintext, NULL);
	jbyte* cipherTextBytes = (*env)->GetPrimitiveArrayCritical(env, ciphertext, NULL);

	int result = xts_encrypt_buffer(ctx, plainTextBytes, cipherTextBytes, length, currentSector);

	(*env)->ReleasePrimitiveArrayCritical(env, plaintext, plainTextBytes, JNI_ABORT);
	(*env)->ReleasePrimitiveArrayCritical(env, ciphertext, cipherTextBytes, 0);

	return result;
}

