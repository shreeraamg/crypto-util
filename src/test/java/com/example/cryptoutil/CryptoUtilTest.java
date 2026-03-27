package com.example.cryptoutil;

import com.example.cryptoutil.domain.EncryptedField;
import com.example.cryptoutil.domain.EncryptionMetadata;
import com.example.cryptoutil.service.CryptoException;
import com.example.cryptoutil.service.DekService;
import com.example.cryptoutil.service.EnvelopeService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.SecureRandom;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Tests CryptoUtil end-to-end with a mocked DekService so no real Key Vault
 * connection is needed. The DekService mock simulates wrap/unwrap using a
 * fixed in-memory key — isolating all crypto logic under test.
 * <p>
 * Stubs are set up per-test rather than in @BeforeEach to satisfy Mockito's
 * strict mode, which fails on stubbings that are declared but never invoked.
 * Tests that exercise guard clauses (null checks, missing __enc, builder
 * validation) never reach the vault, so they need no stubs at all.
 */
@ExtendWith(MockitoExtension.class)
class CryptoUtilTest {

    @Mock
    private DekService dekServiceMock;

    private CryptoUtil cryptoUtil;

    private final byte[] fixedDek = new byte[32];
    private final String fixedEncryptedDek = "bW9ja2VkLXdyYXBwZWQtZGVr";
    private final String fixedKeyId = "master-data-kek/v3";

    @BeforeEach
    void setUp() {
        new SecureRandom().nextBytes(fixedDek);
        cryptoUtil = new CryptoUtil(new EnvelopeService(dekServiceMock));
    }

    // Helpers — called only from tests that actually hit the vault
    private void stubWrap() {
        when(dekServiceMock.generateAndWrap()).thenReturn(
                new DekService.WrappedDek(fixedDek.clone(), fixedEncryptedDek, fixedKeyId)
        );
    }

    private void stubUnwrap() {
        when(dekServiceMock.unwrap(fixedEncryptedDek)).thenReturn(fixedDek.clone());
    }

    // =========================================================
    // Single field
    // =========================================================

    @Test
    void encryptField_returnsEncryptedFieldWithExpectedStructure() {
        stubWrap();
        EncryptedField result = cryptoUtil.encryptField("john.doe@email.com");

        assertThat(result.keyId()).isEqualTo(fixedKeyId);
        assertThat(result.encryptedDek()).isEqualTo(fixedEncryptedDek);
        assertThat(result.ciphertext()).isNotBlank();
        assertThat(result.ciphertext()).isNotEqualTo("john.doe@email.com");
    }

    @Test
    void encryptField_thenDecryptField_returnsOriginalValue() {
        stubWrap();
        stubUnwrap();

        String original = "john.doe@email.com";
        EncryptedField ef = cryptoUtil.encryptField(original);
        String decrypted = cryptoUtil.decryptField(ef);

        assertThat(decrypted).isEqualTo(original);
    }

    @Test
    void encryptField_sameValueTwice_producesDifferentCiphertexts() {
        stubWrap();

        EncryptedField first = cryptoUtil.encryptField("9876543210");
        EncryptedField second = cryptoUtil.encryptField("9876543210");

        // Different IVs — same plaintext always encrypts differently
        assertThat(first.ciphertext()).isNotEqualTo(second.ciphertext());
    }

    @Test
    void encryptField_nullInput_throwsException() {
        // No vault call expected — guard clause fires before DEK generation
        assertThatThrownBy(() -> cryptoUtil.encryptField(null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void decryptField_nullInput_throwsException() {
        // No vault call expected — guard clause fires before unwrapping
        assertThatThrownBy(() -> cryptoUtil.decryptField(null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    // =========================================================
    // Payload level
    // =========================================================

    @Test
    @SuppressWarnings("unchecked")
    void encryptFields_replacesOnlyPiiFields() {
        stubWrap();

        Map<String, Object> encrypted = cryptoUtil.encryptFields(
                buildCustomerPayload(),
                Set.of("customerDetails.firstName",
                        "customerDetails.lastName",
                        "customerDetails.email",
                        "customerDetails.phone")
        );

        // Non-PII field unchanged
        assertThat(encrypted.get("userId")).isEqualTo("1234");

        // PII fields replaced by EncryptedField maps
        Map<String, Object> details = (Map<String, Object>) encrypted.get("customerDetails");
        assertThat(details.get("firstName")).isInstanceOf(Map.class);
        assertThat(details.get("email")).isInstanceOf(Map.class);

        // __enc block present
        assertThat(encrypted).containsKey(EncryptionMetadata.PAYLOAD_KEY);
    }

    @Test
    void encryptFields_thenDecryptFields_restoresAllPiiValues() {
        stubWrap();
        stubUnwrap();

        Map<String, Object> original = buildCustomerPayload();
        Map<String, Object> encrypted = cryptoUtil.encryptFields(
                original,
                Set.of("customerDetails.firstName",
                        "customerDetails.lastName",
                        "customerDetails.email",
                        "customerDetails.phone")
        );
        Map<String, Object> decrypted = cryptoUtil.decryptFields(encrypted);

        assertThat(decrypted).doesNotContainKey(EncryptionMetadata.PAYLOAD_KEY);
        assertThat(decrypted.get("userId")).isEqualTo("1234");

        @SuppressWarnings("unchecked")
        Map<String, Object> details = (Map<String, Object>) decrypted.get("customerDetails");
        assertThat(details.get("firstName")).isEqualTo("John");
        assertThat(details.get("lastName")).isEqualTo("Doe");
        assertThat(details.get("email")).isEqualTo("john.doe@email.com");
        assertThat(details.get("phone")).isEqualTo("9876543210");
    }

    @Test
    void encryptFields_doesNotMutateOriginalPayload() {
        stubWrap();

        Map<String, Object> original = buildCustomerPayload();
        cryptoUtil.encryptFields(original,
                Set.of("customerDetails.firstName", "customerDetails.email"));

        @SuppressWarnings("unchecked")
        Map<String, Object> details = (Map<String, Object>) original.get("customerDetails");
        assertThat(details.get("firstName")).isEqualTo("John");
        assertThat(original).doesNotContainKey(EncryptionMetadata.PAYLOAD_KEY);
    }

    @Test
    void encryptFields_onlyOneVaultRoundTrip() {
        stubWrap();

        cryptoUtil.encryptFields(
                buildCustomerPayload(),
                Set.of("customerDetails.firstName",
                        "customerDetails.lastName",
                        "customerDetails.email",
                        "customerDetails.phone")
        );

        verify(dekServiceMock, times(1)).generateAndWrap();
    }

    @Test
    void decryptFields_missingEncBlock_throwsException() {
        // No vault call expected — missing __enc block is caught before unwrapping
        assertThatThrownBy(() -> cryptoUtil.decryptFields(Map.of("userId", "1234")))
                .isInstanceOf(CryptoException.class)
                .hasMessageContaining("__enc");
    }

    @Test
    void encryptFields_nullPayload_throwsException() {
        // No vault call expected — guard clause fires before DEK generation
        assertThatThrownBy(() -> cryptoUtil.encryptFields(null, Set.of("field")))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void encryptFields_emptyPiiFields_throwsException() {
        // No vault call expected — guard clause fires before DEK generation
        assertThatThrownBy(() -> cryptoUtil.encryptFields(buildCustomerPayload(), Set.of()))
                .isInstanceOf(IllegalArgumentException.class);
    }

    // =========================================================
    // Builder
    // =========================================================

    @Test
    void builder_withoutClient_throwsException() {
        // No vault call expected — builder validation fires before any crypto
        assertThatThrownBy(() -> CryptoUtil.builder().build())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("cryptographyClient");
    }

    // =========================================================
    // Helpers
    // =========================================================

    private Map<String, Object> buildCustomerPayload() {
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("firstName", "John");
        details.put("lastName", "Doe");
        details.put("email", "john.doe@email.com");
        details.put("phone", "9876543210");

        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("userId", "1234");
        payload.put("customerDetails", details);
        return payload;
    }
}