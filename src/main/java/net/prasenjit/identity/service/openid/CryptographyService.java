package net.prasenjit.identity.service.openid;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import lombok.RequiredArgsConstructor;
import net.prasenjit.crypto.store.CryptoKeyFactory;
import net.prasenjit.identity.properties.IdentityProperties;
import org.springframework.stereotype.Service;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;

@Service
@RequiredArgsConstructor
public class CryptographyService {

    private final IdentityProperties identityProperties;
    private final CryptoKeyFactory cryptoKeyFactory;

    public JWKSet loadJwkKeys() {
        int keyCount = identityProperties.getCryptoProperties().getJwkSetCount();
        List<JWK> keys = new ArrayList<>();
        for (int i = 0; i < keyCount; i++) {
            String alias = "jwt-" + i;
            PublicKey key = cryptoKeyFactory.getPublicKey(alias);
            PrivateKey privateKey = cryptoKeyFactory.getPrivateKey(alias,
                    identityProperties.getCryptoProperties().getJwkKeyPassword().toCharArray());
            try {
                RSAKey rsaKey = new RSAKey.Builder((RSAPublicKey) key)
                        .privateKey((RSAPrivateKey) privateKey)
                        .keyIDFromThumbprint()
                        .build();
                keys.add(rsaKey);
            } catch (JOSEException e) {
                throw new RuntimeException("JWK build failed", e);
            }
        }
        return new JWKSet(keys);
    }
}
