package com.mikerussell.filebrowser;

import com.example.mike.browser.encryption.CryptoFailedException;

import java.io.InvalidObjectException;

/**
 * Created by mike on 22/07/15.
 */

public class JniOpenSSLCipher {
	private long ctxPtr = 0;

	public static final int AES_128 = 0;
	public static final int AES_256 = 1;

	static {
		System.loadLibrary("xts");
		init_library();
	}

	public JniOpenSSLCipher(int mode, byte[] key) {
		if (mode == AES_128) {
			if (key.length != 32) {
				throw new IllegalArgumentException("Key should be 32 bytes (256 bit) for AES 128");
			}
		}
		if (mode == AES_256) {
			if (key.length != 64) {
				throw new IllegalArgumentException("Key should be 64 bytes (512 bit) for AES 256");
			}
		}
		ctxPtr = new_cipher_context(mode, key);
	}

	protected void finalize() throws Throwable {
		try {
			free();
		} finally {
			super.finalize();
		}
	}

	public void free() {
		if (ctxPtr != 0) {
			free_cipher_context(ctxPtr);
			ctxPtr = 0;
		}
	}


	public int encryptBuffer(byte[] plainText, byte[] cipherText, int length, long currentSector) throws InvalidObjectException, CryptoFailedException {
		if (ctxPtr == 0) {
			throw new InvalidObjectException("Cipher has already been freed.");
		}
		int encryptedLen =  encrypt_buffer(ctxPtr, plainText, cipherText, length, currentSector);
		if (encryptedLen == 0 && length > 0) {
			throw new CryptoFailedException("Encrypted length is zero. Encryption failed.");
		}
		return encryptedLen;
	}

	public int decryptBuffer(byte[] cipherText, byte[] plainText, int length, long currentSector) throws InvalidObjectException, CryptoFailedException {
		if (ctxPtr == 0) {
			throw new InvalidObjectException("Cipher has already been freed.");
		}
		int decryptedLen = decrypt_buffer(ctxPtr, cipherText, plainText, length, currentSector);
		if (decryptedLen == 0 && length > 0) {
			throw new CryptoFailedException("Decrypted length is zero. Decryption failed.");
		}
		return decryptedLen;
	}

	private static native void init_library();

	private native long new_cipher_context(int mode, byte[] key);
	private native void free_cipher_context(long ctxPtr);
	private native int encrypt_buffer(long ctxPtr, byte[] plainText, byte[] cipherText, int length, long currentSector);
	private native int decrypt_buffer(long ctxPtr, byte[] cipherText, byte[] plainText, int length, long currentSector);
}
