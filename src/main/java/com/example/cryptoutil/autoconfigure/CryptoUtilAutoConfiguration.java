package com.example.cryptoutil.autoconfigure;

import com.azure.security.keyvault.keys.cryptography.CryptographyClient;
import com.example.cryptoutil.CryptoUtil;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;

/**
 * Spring Boot autoconfiguration for {@link CryptoUtil}.
 *
 * <p>Automatically registers a {@link CryptoUtil} bean when:
 * <ol>
 *   <li>{@link CryptographyClient} is on the classpath (Azure SDK present)</li>
 *   <li>A {@link CryptographyClient} bean exists in the application context
 *       (consumer app has configured it with their vault URL and key name)</li>
 *   <li>No existing {@link CryptoUtil} bean is defined (allows override)</li>
 * </ol>
 *
 * <h2>Consumer app configuration</h2>
 * <p>The consumer app is responsible for providing the {@link CryptographyClient}
 * bean. A typical setup using Azure Workload Identity:
 *
 * <pre>{@code
 * @Configuration
 * public class CryptoConfig {
 *
 *     @Value("${crypto.vault-key-identifier}")
 *     private String keyIdentifier;
 *
 *     @Bean
 *     public CryptographyClient cryptographyClient() {
 *         return new CryptographyClientBuilder()
 *             .keyIdentifier(keyIdentifier)
 *             .credential(new DefaultAzureCredentialBuilder().build())
 *             .buildClient();
 *     }
 * }
 * }</pre>
 *
 * <p>With {@code application.yaml}:
 * <pre>{@code
 * crypto:
 *   vault-key-identifier: https://your-keyvault.azure.net/keys/master-data-kek
 * }</pre>
 */
@AutoConfiguration
@ConditionalOnClass(CryptographyClient.class)
public class CryptoUtilAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public CryptoUtil cryptoUtil(
            @SuppressWarnings("SpringJavaInjectionPointsAutowiringInspection")
            CryptographyClient cryptographyClient) {
        return new CryptoUtil(cryptographyClient);
    }

}
