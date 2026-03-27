package com.example.cryptoutil;

import com.azure.security.keyvault.keys.cryptography.CryptographyClient;
import com.example.cryptoutil.domain.EncryptedField;
import com.example.cryptoutil.service.DekService;
import com.example.cryptoutil.service.EnvelopeService;

import java.util.Map;
import java.util.Set;

/**
 * Public entry point for envelope encryption and decryption of PII fields.
 *
 * <h2>Usage — Spring Boot (recommended)</h2>
 * <p>If your application has a {@link CryptographyClient} bean configured,
 * the {@link com.example.cryptoutil.autoconfigure.CryptoUtilAutoConfiguration}
 * will register a {@code CryptoUtil} bean automatically. Inject it normally:
 *
 * <pre>{@code
 * @Autowired
 * CryptoUtil cryptoUtil;
 * }</pre>
 *
 * <h2>Usage — plain Java (no Spring)</h2>
 * <pre>{@code
 * CryptographyClient client = new CryptographyClientBuilder()
 *     .keyIdentifier("https://your-vault.vault.azure.net/keys/your-kek")
 *     .credential(new DefaultAzureCredentialBuilder().build())
 *     .buildClient();
 *
 * CryptoUtil cryptoUtil = CryptoUtil.builder()
 *     .cryptographyClient(client)
 *     .build();
 * }</pre>
 *
 * <h2>Field-level encryption</h2>
 * <pre>{@code
 * EncryptedField ef = cryptoUtil.encryptField("john.doe@email.com");
 * String plain      = cryptoUtil.decryptField(ef);
 * }</pre>
 *
 * <h2>Payload-level encryption</h2>
 * <pre>{@code
 * Map<String, Object> encrypted = cryptoUtil.encryptFields(
 *     payload,
 *     Set.of("customerDetails.firstName",
 *            "customerDetails.lastName",
 *            "customerDetails.email",
 *            "customerDetails.phone")
 * );
 *
 * Map<String, Object> decrypted = cryptoUtil.decryptFields(encrypted);
 * }</pre>
 */
public class CryptoUtil {

    private final EnvelopeService envelopeService;

    public CryptoUtil(CryptographyClient cryptographyClient) {
        this.envelopeService = new EnvelopeService(new DekService(cryptographyClient));
    }

    // ── Constructor kept package-private for testing via EnvelopeService mock ──
    CryptoUtil(EnvelopeService envelopeService) {
        this.envelopeService = envelopeService;
    }

    // =========================================================
    // Single-field API
    // =========================================================

    /**
     * Encrypts a single plaintext string.
     *
     * <p>Generates a fresh DEK, encrypts the value with AES-256-GCM,
     * wraps the DEK via Key Vault (one vault round-trip), and returns
     * a self-contained {@link EncryptedField}.
     *
     * @param plaintext the PII value to encrypt
     * @return {@link EncryptedField} containing keyId, encryptedDek, and ciphertext
     */
    public EncryptedField encryptField(String plaintext) {
        return envelopeService.encryptField(plaintext);
    }

    /**
     * Decrypts a single {@link EncryptedField} back to its plaintext value.
     *
     * <p>Unwraps the DEK from Key Vault (one vault round-trip) then
     * decrypts locally with AES-256-GCM.
     *
     * @param encryptedField produced by {@link #encryptField}
     * @return original plaintext string
     */
    public String decryptField(EncryptedField encryptedField) {
        return envelopeService.decryptField(encryptedField);
    }

    // =========================================================
    // Payload-level API
    // =========================================================

    /**
     * Encrypts nominated PII fields within a payload map.
     *
     * <p>One DEK is generated for the entire call (one vault round-trip).
     * All nominated fields are encrypted with that single DEK. Non-PII fields
     * are copied unchanged. An {@code __enc} metadata block is added at the root.
     *
     * <p>Field paths support dot-notation for nested fields:
     * {@code "customerDetails.firstName"}
     *
     * @param payload   original event map — not mutated
     * @param piiFields dot-notation paths of fields to encrypt
     * @return new map with PII encrypted and {@code __enc} block injected
     */
    public Map<String, Object> encryptFields(Map<String, Object> payload, Set<String> piiFields) {
        return envelopeService.encryptFields(payload, piiFields);
    }

    /**
     * Decrypts all PII fields in a previously encrypted payload map.
     *
     * <p>Reads the {@code __enc} block, unwraps the DEK from Key Vault
     * (one vault round-trip), decrypts all {@link EncryptedField} values,
     * and returns a clean map with plaintext PII restored.
     * The {@code __enc} block is removed from the result.
     *
     * @param encryptedPayload map produced by {@link #encryptFields}
     * @return new map with plaintext PII values restored
     */
    public Map<String, Object> decryptFields(Map<String, Object> encryptedPayload) {
        return envelopeService.decryptFields(encryptedPayload);
    }

    // =========================================================
    // Builder
    // =========================================================

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {

        private CryptographyClient cryptographyClient;

        private Builder() {
        }

        /**
         * The Azure Key Vault {@link CryptographyClient} scoped to your KEK.
         * Consumer application is responsible for building this with
         * {@code DefaultAzureCredential} and the correct key identifier.
         */
        public Builder cryptographyClient(CryptographyClient cryptographyClient) {
            this.cryptographyClient = cryptographyClient;
            return this;
        }

        public CryptoUtil build() {
            if (cryptographyClient == null) {
                throw new IllegalStateException("cryptographyClient must be provided");
            }
            return new CryptoUtil(cryptographyClient);
        }
    }

}
