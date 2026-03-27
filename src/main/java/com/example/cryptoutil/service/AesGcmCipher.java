package com.example.cryptoutil.service;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Base64;

/**
 * Stateless AES-256-GCM cipher.
 *
 * <p>Wire format per encrypted value (all concatenated, then Base64-encoded):
 * <pre>
 *   [12 bytes — random IV][N bytes — ciphertext][16 bytes — GCM auth tag]
 * </pre>
 *
 * <p>The IV is generated fresh per encryption call, so encrypting the same
 * plaintext twice with the same key always produces different ciphertext.
 * The auth tag guarantees integrity — any tampering causes decryption to fail.
 */
class AesGcmCipher {
    private static final String ALGORITHM      = "AES/GCM/NoPadding";
    private static final int    IV_LENGTH      = 12;   // bytes — NIST recommended for GCM
    private static final int    TAG_LENGTH_BIT = 128;  // 16 bytes

    static {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private final SecureRandom secureRandom = new SecureRandom();

    /**
     * Encrypts {@code plaintext} with the provided raw AES-256 key bytes.
     *
     * @param plaintext     UTF-8 string to encrypt
     * @param rawKeyBytes   32-byte AES-256 key (the plaintext DEK)
     * @return Base64-encoded {@code [IV][ciphertext][auth tag]}
     */
    String encrypt(String plaintext, byte[] rawKeyBytes) throws Exception {
        byte[] iv = new byte[IV_LENGTH];
        secureRandom.nextBytes(iv);

        Cipher cipher = Cipher.getInstance(ALGORITHM, "BC");
        cipher.init(Cipher.ENCRYPT_MODE, toKey(rawKeyBytes), new GCMParameterSpec(TAG_LENGTH_BIT, iv));

        byte[] ciphertext = cipher.doFinal(plaintext.getBytes());

        // Prepend IV so decrypt can extract it
        byte[] result = new byte[IV_LENGTH + ciphertext.length];
        System.arraycopy(iv,         0, result, 0,         IV_LENGTH);
        System.arraycopy(ciphertext, 0, result, IV_LENGTH, ciphertext.length);

        return Base64.getEncoder().encodeToString(result);
    }

    /**
     * Decrypts a Base64-encoded {@code [IV][ciphertext][auth tag]} back to plaintext.
     *
     * @param base64Ciphertext  value produced by {@link #encrypt}
     * @param rawKeyBytes       32-byte AES-256 key (the plaintext DEK)
     * @return original plaintext string
     */
    String decrypt(String base64Ciphertext, byte[] rawKeyBytes) throws Exception {
        byte[] combined = Base64.getDecoder().decode(base64Ciphertext);

        byte[] iv         = new byte[IV_LENGTH];
        byte[] ciphertext = new byte[combined.length - IV_LENGTH];
        System.arraycopy(combined, 0,         iv,         0, IV_LENGTH);
        System.arraycopy(combined, IV_LENGTH, ciphertext, 0, ciphertext.length);

        Cipher cipher = Cipher.getInstance(ALGORITHM, "BC");
        cipher.init(Cipher.DECRYPT_MODE, toKey(rawKeyBytes), new GCMParameterSpec(TAG_LENGTH_BIT, iv));

        return new String(cipher.doFinal(ciphertext));
    }

    private static SecretKey toKey(byte[] rawKeyBytes) {
        if (rawKeyBytes.length != 32) {
            throw new IllegalArgumentException(
                    "DEK must be 32 bytes for AES-256, got: " + rawKeyBytes.length);
        }
        return new SecretKeySpec(rawKeyBytes, "AES");
    }

}
