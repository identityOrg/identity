package net.prasenjit.identity.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.time.Duration;

@Data
@Component
@ConfigurationProperties(prefix = "identity")
public class IdentityProperties {
    private CryptoProperties cryptoProperties = new CryptoProperties();
    private Duration userPasswordValidity = Duration.ofDays(60);
    private Duration e2eKeyValidity = Duration.ofHours(6);
}
