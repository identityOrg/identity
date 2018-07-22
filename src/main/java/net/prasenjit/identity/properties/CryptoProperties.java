package net.prasenjit.identity.properties;

import lombok.Data;
import org.springframework.core.io.Resource;

import java.util.List;

@Data
public class CryptoProperties {
    /**
     * Location of the keystore as a URL
     */
    private Resource keyStoreLocation;
    private String keyStorePassword;
    private String keyStoreProvider;
    private String keyStoreType;
    private String mainKeyPassword = "main";
    private String clientKeyPassword;

    private List<String> cyclePassword;
}
