package com.example.cryptoutil.domain;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * The {@code __enc} metadata block embedded at the root of an encrypted payload map.
 *
 * <p>When {@code CryptoUtil.encryptFields()} is called, one DEK is generated for
 * the entire payload. The DEK is wrapped by the KEK in Key Vault and stored here
 * alongside all PII field ciphertexts. Consumers parse this block first to obtain
 * the encrypted DEK before decrypting individual fields.
 *
 * <pre>{@code
 * {
 *   "__enc": {
 *     "keyId"        : "master-data-kek/v3",
 *     "encryptedDek" : "base64=="
 *   },
 *   "userId"          : "1234",
 *   "customerDetails" : {
 *     "firstName": "aGVs...base64==",
 *     ...
 *   }
 * }
 * }</pre>
 */
public record EncryptionMetadata(

        @JsonProperty("keyId")
        String keyId,

        @JsonProperty("encryptedDek")
        String encryptedDek

) {
    public static final String PAYLOAD_KEY = "__enc";

    @JsonCreator
    public EncryptionMetadata(
            @JsonProperty("keyId") String keyId,
            @JsonProperty("encryptedDek") String encryptedDek
    ) {
        if (keyId == null || keyId.isBlank()) throw new IllegalArgumentException("keyId must not be blank");
        if (encryptedDek == null || encryptedDek.isBlank())
            throw new IllegalArgumentException("encryptedDek must not be blank");

        this.keyId = keyId;
        this.encryptedDek = encryptedDek;
    }
}
