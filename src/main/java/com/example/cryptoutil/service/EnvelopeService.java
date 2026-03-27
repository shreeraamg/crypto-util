package com.example.cryptoutil.service;

import com.example.cryptoutil.domain.EncryptedField;
import com.example.cryptoutil.domain.EncryptionMetadata;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * Orchestrates envelope encryption at both field and payload level.
 *
 * <p>This is the internal engine behind {@code CryptoUtil}. It ties together
 * {@link DekService} (Key Vault DEK wrap/unwrap) and {@link AesGcmCipher}
 * (AES-256-GCM field encryption) into the two-level API.
 */
public class EnvelopeService {

    private final DekService dekService;
    private final AesGcmCipher cipher;
    private final ObjectMapper objectMapper;

    public EnvelopeService(DekService dekService) {
        this.dekService = dekService;
        this.cipher = new AesGcmCipher();
        this.objectMapper = new ObjectMapper();
    }

    // =========================================================
    // Single-field API
    // =========================================================

    /**
     * Encrypts a single plaintext string.
     *
     * <p>Generates a fresh DEK, encrypts the value, wraps the DEK via
     * Key Vault, returns a self-contained {@link EncryptedField} with
     * {@code keyId}, {@code encryptedDek}, and {@code ciphertext}.
     *
     * <p>One vault round-trip (wrapKey) per call.
     */
    public EncryptedField encryptField(String plaintext) {
        if (plaintext == null) throw new IllegalArgumentException("plaintext must not be null");

        DekService.WrappedDek wrappedDek = dekService.generateAndWrap();
        try {
            String ciphertext = cipher.encrypt(plaintext, wrappedDek.plaintextDek());
            return new EncryptedField(wrappedDek.keyId(), wrappedDek.encryptedDek(), ciphertext);
        } catch (Exception e) {
            throw new CryptoException("Field encryption failed", e);
        } finally {
            wrappedDek.clearPlaintext();
        }
    }

    /**
     * Decrypts a single {@link EncryptedField}.
     *
     * <p>Unwraps the DEK from Key Vault (one vault round-trip per call),
     * then decrypts the ciphertext locally.
     */
    public String decryptField(EncryptedField encryptedField) {
        if (encryptedField == null) throw new IllegalArgumentException("encryptedField must not be null");

        byte[] plaintextDek = dekService.unwrap(encryptedField.encryptedDek());
        try {
            return cipher.decrypt(encryptedField.ciphertext(), plaintextDek);
        } catch (Exception e) {
            throw new CryptoException("Field decryption failed", e);
        } finally {
            java.util.Arrays.fill(plaintextDek, (byte) 0);
        }
    }

    // =========================================================
    // Payload-level API
    // =========================================================

    /**
     * Encrypts the specified PII fields within a payload map.
     *
     * <p>One DEK is generated for the entire call (one vault round-trip).
     * All nominated fields are encrypted with that single DEK. The DEK
     * is then wrapped and embedded in an {@code __enc} block at the root
     * of the returned map. Non-PII fields are copied as-is.
     *
     * <p>Supports dot-notation for nested fields, e.g.
     * {@code "customerDetails.firstName"}.
     *
     * @param payload   original event map (not mutated)
     * @param piiFields set of field paths to encrypt
     * @return new map with PII values replaced by JSON-serialised
     * {@link EncryptedField} objects and {@code __enc} block added
     */
    public Map<String, Object> encryptFields(Map<String, Object> payload, Set<String> piiFields) {
        if (payload == null) throw new IllegalArgumentException("payload must not be null");
        if (piiFields == null || piiFields.isEmpty()) throw new IllegalArgumentException("piiFields must not be empty");

        DekService.WrappedDek wrappedDek = dekService.generateAndWrap();
        try {
            Map<String, Object> result = deepCopy(payload);

            for (String fieldPath : piiFields) {
                String plaintext = extractString(result, fieldPath);
                if (plaintext == null) continue; // field absent — skip silently

                String ciphertext = cipher.encrypt(plaintext, wrappedDek.plaintextDek());
                EncryptedField encField = new EncryptedField(
                        wrappedDek.keyId(),
                        wrappedDek.encryptedDek(),
                        ciphertext
                );
                setField(result, fieldPath, objectMapper.convertValue(encField, Map.class));
            }

            // Inject __enc block at root — carries shared keyId and encryptedDek
            result.put(EncryptionMetadata.PAYLOAD_KEY,
                    objectMapper.convertValue(
                            new EncryptionMetadata(wrappedDek.keyId(), wrappedDek.encryptedDek()),
                            Map.class
                    ));
            return result;

        } catch (CryptoException e) {
            throw e;
        } catch (Exception e) {
            throw new CryptoException("Payload encryption failed", e);
        } finally {
            wrappedDek.clearPlaintext();
        }
    }

    /**
     * Decrypts all {@link EncryptedField} values in a previously encrypted payload.
     *
     * <p>Reads the {@code __enc} block to get the encrypted DEK, unwraps it
     * via Key Vault (one vault round-trip for the entire payload), then decrypts
     * every field whose value matches the {@link EncryptedField} structure.
     * Non-PII fields and the {@code __enc} block are stripped from the result.
     *
     * @param encryptedPayload map produced by {@link #encryptFields}
     * @return new map with plaintext PII values restored; {@code __enc} removed
     */
    @SuppressWarnings("unchecked")
    public Map<String, Object> decryptFields(Map<String, Object> encryptedPayload) {
        if (encryptedPayload == null) throw new IllegalArgumentException("encryptedPayload must not be null");

        Object encBlock = encryptedPayload.get(EncryptionMetadata.PAYLOAD_KEY);
        if (encBlock == null) {
            throw new CryptoException("Missing __enc block — payload was not encrypted by this library");
        }

        EncryptionMetadata metadata = objectMapper.convertValue(encBlock, EncryptionMetadata.class);
        byte[] plaintextDek = dekService.unwrap(metadata.encryptedDek());

        try {
            Map<String, Object> result = deepCopy(encryptedPayload);
            result.remove(EncryptionMetadata.PAYLOAD_KEY);
            decryptAllFields(result, plaintextDek);
            return result;
        } catch (CryptoException e) {
            throw e;
        } catch (Exception e) {
            throw new CryptoException("Payload decryption failed", e);
        } finally {
            java.util.Arrays.fill(plaintextDek, (byte) 0);
        }
    }

    // =========================================================
    // Private helpers
    // =========================================================

    /**
     * Recursively decrypt any value that looks like an EncryptedField.
     */
    @SuppressWarnings("unchecked")
    private void decryptAllFields(Map<String, Object> map, byte[] plaintextDek) throws Exception {
        for (Map.Entry<String, Object> entry : map.entrySet()) {
            Object value = entry.getValue();

            if (value instanceof Map<?, ?> nested) {
                Map<String, Object> nestedMap = (Map<String, Object>) nested;

                // Check if this nested map is an EncryptedField structure
                if (isEncryptedField(nestedMap)) {
                    EncryptedField ef = objectMapper.convertValue(nestedMap, EncryptedField.class);
                    entry.setValue(cipher.decrypt(ef.ciphertext(), plaintextDek));
                } else {
                    // Recurse into nested objects
                    decryptAllFields(nestedMap, plaintextDek);
                }
            }
        }
    }

    private boolean isEncryptedField(Map<String, Object> map) {
        return map.containsKey("keyId")
                && map.containsKey("encryptedDek")
                && map.containsKey("ciphertext");
    }

    /**
     * Extract a String value from a map using dot-notation path.
     */
    @SuppressWarnings("unchecked")
    private String extractString(Map<String, Object> map, String path) {
        String[] parts = path.split("\\.", 2);
        Object value = map.get(parts[0]);
        if (value == null) return null;
        if (parts.length == 1) return value instanceof String s ? s : String.valueOf(value);
        if (value instanceof Map<?, ?> nested) return extractString((Map<String, Object>) nested, parts[1]);
        return null;
    }

    /**
     * Set a value in a map using dot-notation path, creating intermediate maps as needed.
     */
    @SuppressWarnings("unchecked")
    private void setField(Map<String, Object> map, String path, Object value) {
        String[] parts = path.split("\\.", 2);
        if (parts.length == 1) {
            map.put(parts[0], value);
            return;
        }
        Object nested = map.get(parts[0]);
        if (!(nested instanceof Map)) {
            nested = new HashMap<>();
            map.put(parts[0], nested);
        }
        setField((Map<String, Object>) nested, parts[1], value);
    }

    /**
     * Shallow-to-deep copy of a map structure (copies nested maps, leaves leaf values as-is).
     */
    @SuppressWarnings("unchecked")
    private Map<String, Object> deepCopy(Map<String, Object> original) {
        Map<String, Object> copy = new HashMap<>();
        for (Map.Entry<String, Object> entry : original.entrySet()) {
            Object value = entry.getValue();
            if (value instanceof Map<?, ?> nestedMap) {
                copy.put(entry.getKey(), deepCopy((Map<String, Object>) nestedMap));
            } else {
                copy.put(entry.getKey(), value);
            }
        }
        return copy;
    }

}
