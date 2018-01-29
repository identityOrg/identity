package net.prasenjit.identity.properties;

import org.springframework.core.io.Resource;

import lombok.Data;

@Data
public class CryptoProperties {
	private Resource keyStoreLocation;
	private String keyStorePassword;
	private String keyStoreProvider;
	private String keyStoreType;
	private String mainKeyPassword;
	private String clientKeyPassword;
}
