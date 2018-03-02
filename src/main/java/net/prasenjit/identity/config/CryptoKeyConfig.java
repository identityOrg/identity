package net.prasenjit.identity.config;

import lombok.RequiredArgsConstructor;
import net.prasenjit.crypto.TextEncryptor;
import net.prasenjit.crypto.impl.AesEncryptor;
import net.prasenjit.crypto.store.CryptoKeyFactory;
import net.prasenjit.identity.properties.IdentityProperties;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;

import javax.crypto.SecretKey;
import java.io.IOException;

@Configuration
@RequiredArgsConstructor
public class CryptoKeyConfig {

    private final IdentityProperties properties;

    @Bean
    public CryptoKeyFactory keyStore() throws IOException {
        return CryptoKeyFactory.builder().location(properties.getCryptoProperties().getKeyStoreLocation().getURL())
                .password(properties.getCryptoProperties().getKeyStorePassword())
                .providerName(properties.getCryptoProperties().getKeyStoreProvider())
                .type(properties.getCryptoProperties().getKeyStoreType()).build();
    }

    @Bean
    @Primary
    @Qualifier("main")
    public TextEncryptor mainEncryptor(CryptoKeyFactory keyFactory) {
        SecretKey aesKey = keyFactory.getSecretKey("main",
                properties.getCryptoProperties().getMainKeyPassword().toCharArray());
        return new AesEncryptor(aesKey);
    }

    @Bean
    @Qualifier("client-password")
    public TextEncryptor clientEncryptor(CryptoKeyFactory keyFactory) {
        String clientKeyPassword = properties.getCryptoProperties().getClientKeyPassword();
        SecretKey secretKey = keyFactory.getSecretKey("client-password", clientKeyPassword.toCharArray());
        return new AesEncryptor(secretKey);
    }
}
