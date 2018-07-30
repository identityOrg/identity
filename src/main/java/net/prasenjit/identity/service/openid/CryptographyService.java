package net.prasenjit.identity.service.openid;

import com.nimbusds.jose.jwk.RSAKey;
import lombok.RequiredArgsConstructor;
import net.minidev.json.JSONObject;
import net.prasenjit.identity.entity.JWKKey;
import net.prasenjit.identity.properties.IdentityProperties;
import net.prasenjit.identity.repository.JWKKeyRepository;
import net.prasenjit.identity.security.crypto.CyclicEncryptorFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.CollectionUtils;

import javax.crypto.Cipher;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class CryptographyService {

    private static final int PRIVATE = Cipher.PRIVATE_KEY;
    private static final int PUBLIC = Cipher.PUBLIC_KEY;
    private final JWKKeyRepository keyRepository;
    private final IdentityProperties identityProperties;
    private final CyclicEncryptorFactory encryptorFactory;

    @Transactional(readOnly = true)
    public List<JSONObject> getLast5Keys() {
        List<JWKKey> keysToreturn = getOrGenerateJwkKeys();
        return keysToreturn.stream().map(jwkKey -> {
            Key publicKey = unwrapKey(jwkKey.getPublicKey(), jwkKey.getCreationDate(), PUBLIC);
            RSAKey rsaKey = new RSAKey.Builder((RSAPublicKey) publicKey)
                    .keyID(jwkKey.getId().toString()).build();
            return rsaKey.toJSONObject();
        }).collect(Collectors.toList());
    }

    public List<JWKKey> getOrGenerateJwkKeys() {
        List<JWKKey> keysToreturn = new ArrayList<>();
        List<JWKKey> jwkKeys = keyRepository.findAll();
        if (CollectionUtils.isEmpty(jwkKeys)) {
            JWKKey lastKey = generateKeyPair();
            keysToreturn.add(lastKey);
        } else {
            JWKKey lastKey = jwkKeys.get(0);
            LocalDate keyDate = lastKey.getCreationDate().toLocalDate();
            if (!LocalDate.now().equals(keyDate)) {
                lastKey = generateKeyPair();
                keysToreturn.add(lastKey);
                for (int i = 0; i < 4 && i < jwkKeys.size(); i++) {
                    keysToreturn.add(jwkKeys.get(i));
                }
            } else {
                keysToreturn.addAll(jwkKeys);
            }
        }
        return keysToreturn;
    }

    private JWKKey generateKeyPair() {
        try {
            LocalDateTime creationDate = LocalDateTime.now();
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(identityProperties.getCryptoProperties().getJwkKeySize());
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            JWKKey keyEntry = new JWKKey();
            keyEntry.setPrivateKey(wrapKey(keyPair.getPrivate(), creationDate));
            keyEntry.setPublicKey(wrapKey(keyPair.getPublic(), creationDate));
            keyEntry.setCreationDate(creationDate);
            return keyRepository.saveAndFlush(keyEntry);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private String wrapKey(Key key, LocalDateTime encryptionDate) {
        return encryptorFactory.createEncryptor(encryptionDate).wrapKey(key);
    }

    private Key unwrapKey(String encodedKey, LocalDateTime encryptionDate, int type) {
        return encryptorFactory.createEncryptor(encryptionDate).unwrapKey(encodedKey, "RSA", type);
    }

    public PrivateKey getSigningKey(JWKKey jwkKey) {
        return (PrivateKey) unwrapKey(jwkKey.getPrivateKey(), jwkKey.getCreationDate(), PRIVATE);
    }
}
