package net.prasenjit.identity.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.temporal.ChronoUnit;

@Data
@Component
@ConfigurationProperties(prefix = "identity")
public class IdentityProperties {
    private CryptoProperties cryptoProperties = new CryptoProperties();
    private Duration userPasswordValidity = Duration.of(1, ChronoUnit.HOURS);
}
