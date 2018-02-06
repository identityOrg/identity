package net.prasenjit.identity.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Data
@Component
@ConfigurationProperties(prefix = "identity")
public class IdentityProperties {
    private CryptoProperties cryptoProperties = new CryptoProperties();
}
