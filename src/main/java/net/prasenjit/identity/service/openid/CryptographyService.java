/*
 *    Copyright 2018 prasenjit-net
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

package net.prasenjit.identity.service.openid;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
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
        List<JWK> keys = new ArrayList<>();
        String alias = "jwk-enc";
        PublicKey key = cryptoKeyFactory.getPublicKey(alias);
        PrivateKey privateKey = cryptoKeyFactory.getPrivateKey(alias,
                identityProperties.getCryptoProperties().getJwkEncKeyPassword().toCharArray());
        RSAKey rsaKey = new RSAKey.Builder((RSAPublicKey) key)
                .privateKey((RSAPrivateKey) privateKey)
                .keyID(alias)
                .keyUse(KeyUse.ENCRYPTION)
                .build();
        keys.add(rsaKey);
        alias = "jwk-sig";
        key = cryptoKeyFactory.getPublicKey(alias);
        privateKey = cryptoKeyFactory.getPrivateKey(alias,
                identityProperties.getCryptoProperties().getJwkEncKeyPassword().toCharArray());
        rsaKey = new RSAKey.Builder((RSAPublicKey) key)
                .privateKey((RSAPrivateKey) privateKey)
                .keyID(alias)
                .keyUse(KeyUse.SIGNATURE)
                .build();
        keys.add(rsaKey);
        return new JWKSet(keys);
    }
}
