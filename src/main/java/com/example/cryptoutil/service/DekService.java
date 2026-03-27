package com.example.cryptoutil.service;

import com.azure.security.keyvault.keys.cryptography.CryptographyClient;
import com.azure.security.keyvault.keys.cryptography.models.KeyWrapAlgorithm;
import com.azure.security.keyvault.keys.cryptography.models.UnwrapResult;
import com.azure.security.keyvault.keys.cryptography.models.WrapResult;

import java.security.SecureRandom;
import java.util.Base64;

/**
 * Generates, wraps, and unwraps Data Encryption Keys (DEKs) using
 * Azure Key Vault as the KEK store.
 *
 * <p>The plaintext DEK is a 32-byte random value (AES-256).
 * It is generated in memory, used to encrypt PII fields, then wrapped
 * (encrypted) by the KEK inside Key Vault. The plaintext DEK is
 * discarded after wrapping.
 *
 * <p>The wrapped DEK (ciphertext of the DEK) is what gets persisted
 * alongside the encrypted payload — never the plaintext DEK.
 */
public class DekService {

    private static final KeyWrapAlgorithm WRAP_ALGORITHM = KeyWrapAlgorithm.RSA_OAEP_256;
    private static final int DEK_LENGTH = 32; // bytes — AES-256

    private final CryptographyClient cryptographyClient;
    private final SecureRandom secureRandom = new SecureRandom();

    public DekService(CryptographyClient cryptographyClient) {
        this.cryptographyClient = cryptographyClient;
    }

    /**
     * Generates a fresh 32-byte random DEK, wraps it via Key Vault,
     * and returns a {@link WrappedDek} containing both the plaintext
     * DEK (for immediate use) and the Base64-encoded wrapped DEK
     * (for storage in the message).
     *
     * <p>Callers must discard the plaintext DEK after use.
     */
    public WrappedDek generateAndWrap() {
        byte[] plaintextDek = new byte[DEK_LENGTH];
        secureRandom.nextBytes(plaintextDek);

        WrapResult result = cryptographyClient.wrapKey(WRAP_ALGORITHM, plaintextDek);
        String encryptedDek = Base64.getEncoder().encodeToString(result.getEncryptedKey());
        String keyId = cryptographyClient.getKey().getId();

        return new WrappedDek(plaintextDek, encryptedDek, keyId);
    }

    /**
     * Unwraps a previously wrapped DEK by calling Key Vault.
     * Key Vault enforces IAM — if the caller's identity does not have
     * {@code unwrapKey} permission, this throws an exception.
     *
     * @param encryptedDek Base64-encoded wrapped DEK from the message
     * @return plaintext 32-byte DEK — caller must discard after use
     */
    public byte[] unwrap(String encryptedDek) {
        byte[] encryptedDekBytes = Base64.getDecoder().decode(encryptedDek);
        UnwrapResult result = cryptographyClient.unwrapKey(WRAP_ALGORITHM, encryptedDekBytes);
        return result.getKey();
    }

    /**
     * Holds the plaintext DEK and its wrapped form together
     * for the duration of a single encrypt operation.
     * Plaintext DEK must be zeroed/discarded after the encrypt is complete.
     */
    public record WrappedDek(
            byte[] plaintextDek,
            String encryptedDek,
            String keyId
    ) {
        /**
         * Zero the plaintext DEK bytes from memory.
         */
        public void clearPlaintext() {
            java.util.Arrays.fill(plaintextDek, (byte) 0);
        }
    }

}
