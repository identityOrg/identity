package net.prasenjit.identity.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import lombok.Data;

@Data
@Component
@ConfigurationProperties(prefix = "identity")
public class IdentityProperties {
	private CryptoProperties cryptoProperties = new CryptoProperties();
}
