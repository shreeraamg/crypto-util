package com.example.cryptoutil.domain;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Wire format for a single encrypted PII field.
 *
 * <p>Serialises to inspectable nested JSON so consumers can observe
 * the keyId and verify the structure without decrypting:
 *
 * <pre>{@code
 * {
 *   "keyId"        : "master-data-kek/v3",
 *   "encryptedDek" : "base64==",
 *   "ciphertext"   : "base64=="
 * }
 * }</pre>
 *
 * <p>The {@code ciphertext} field decodes to:
 * {@code [12-byte IV][N-byte AES-GCM ciphertext][16-byte auth tag]}
 *
 * <p>Each EncryptedField is self-contained — it carries everything
 * needed to decrypt it in isolation via {@code CryptoUtil.decryptField()}.
 */
public record EncryptedField(

        @JsonProperty("keyId")
        String keyId,

        @JsonProperty("encryptedDek")
        String encryptedDek,

        @JsonProperty("ciphertext")
        String ciphertext

) {
    @JsonCreator
    public EncryptedField(
            @JsonProperty("keyId") String keyId,
            @JsonProperty("encryptedDek") String encryptedDek,
            @JsonProperty("ciphertext") String ciphertext
    ) {
        if (keyId == null || keyId.isBlank()) throw new IllegalArgumentException("keyId must not be blank");

        if (encryptedDek == null || encryptedDek.isBlank())
            throw new IllegalArgumentException("encryptedDek must not be blank");

        if (ciphertext == null || ciphertext.isBlank())
            throw new IllegalArgumentException("ciphertext must not be blank");

        this.keyId = keyId;
        this.encryptedDek = encryptedDek;
        this.ciphertext = ciphertext;
    }
}