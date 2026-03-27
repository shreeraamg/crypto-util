package com.example.cryptoutil.service;

/**
 * Unchecked exception thrown when an encryption or decryption operation fails.
 *
 * <p>Wraps checked exceptions from the AES-GCM cipher and Azure SDK so
 * callers do not have to handle checked exceptions for every encrypt/decrypt call.
 *
 * <p>Common causes:
 * <ul>
 *   <li>Key Vault authentication failure (identity lacks wrapKey/unwrapKey permission)</li>
 *   <li>GCM auth tag verification failure (tampered ciphertext)</li>
 *   <li>Malformed Base64 in an EncryptedField value</li>
 *   <li>DEK length mismatch (not 32 bytes)</li>
 * </ul>
 */
public class CryptoException extends RuntimeException {

    public CryptoException(String message) {
        super(message);
    }

    public CryptoException(String message, Throwable cause) {
        super(message, cause);
    }

}