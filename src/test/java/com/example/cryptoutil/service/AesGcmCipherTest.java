package com.example.cryptoutil.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;

import static org.assertj.core.api.Assertions.*;

class AesGcmCipherTest {

    private AesGcmCipher cipher;
    private byte[] key;

    @BeforeEach
    void setUp() {
        cipher = new AesGcmCipher();
        key = new byte[32];
        new SecureRandom().nextBytes(key);
    }

    @Test
    void encryptThenDecrypt_returnsOriginalPlaintext() throws Exception {
        String plaintext = "john.doe@email.com";
        String ciphertext = cipher.encrypt(plaintext, key);
        String decrypted = cipher.decrypt(ciphertext, key);

        assertThat(decrypted).isEqualTo(plaintext);
    }

    @Test
    void encryptTwice_producesDifferentCiphertexts() throws Exception {
        String plaintext = "same-value";
        String first = cipher.encrypt(plaintext, key);
        String second = cipher.encrypt(plaintext, key);

        // Different IVs mean the same plaintext encrypts differently every time
        assertThat(first).isNotEqualTo(second);
    }

    @Test
    void decrypt_withWrongKey_throwsException() {
        byte[] wrongKey = new byte[32];
        new SecureRandom().nextBytes(wrongKey);

        assertThatThrownBy(() -> {
            String ciphertext = cipher.encrypt("sensitive", key);
            cipher.decrypt(ciphertext, wrongKey);
        }).isInstanceOf(Exception.class);
    }

    @Test
    void decrypt_withTamperedCiphertext_throwsException() throws Exception {
        String ciphertext = cipher.encrypt("sensitive", key);
        byte[] ciphertextBytes = java.util.Base64.getDecoder().decode(ciphertext);
        // Flip a bit in the auth tag (last 16 bytes)
        ciphertextBytes[ciphertextBytes.length - 1] ^= (byte) 0xFF;
        String tampered = java.util.Base64.getEncoder().encodeToString(ciphertextBytes);

        assertThatThrownBy(() -> cipher.decrypt(tampered, key))
                .isInstanceOf(Exception.class);
    }

    @Test
    void encrypt_withInvalidKeyLength_throwsException() {
        byte[] shortKey = new byte[16]; // AES-128, not AES-256
        assertThatThrownBy(() -> cipher.encrypt("value", shortKey))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("32 bytes");
    }
}