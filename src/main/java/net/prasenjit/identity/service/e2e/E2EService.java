package net.prasenjit.identity.service.e2e;

import com.nimbusds.jose.jwk.RSAKey;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import net.prasenjit.crypto.endtoend.RsaEncryptorBuilder;
import net.prasenjit.identity.security.crypto.CyclicEncryptorFactory;
import net.prasenjit.identity.entity.client.Client;
import net.prasenjit.identity.entity.E2EKey;
import net.prasenjit.identity.entity.User;
import net.prasenjit.identity.model.Profile;
import net.prasenjit.identity.properties.IdentityProperties;
import net.prasenjit.identity.repository.E2EKeyRepository;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.time.LocalDateTime;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class E2EService {

    private static final int PRIVATE = Cipher.PRIVATE_KEY;
    private static final int PUBLIC = Cipher.PUBLIC_KEY;
    private final E2EKeyRepository keyRepository;
    private final IdentityProperties identityProperties;
    private final CyclicEncryptorFactory encryptorFactory;

    public RSAKey getAsymmetricKey(Authentication authentication) {
        E2EKey e2EKey = findOrGenerateKeyPair(authentication);
        Key publicKey = unwrapKey(e2EKey.getCurrentPublicKey(), e2EKey.getCreationDate(), PUBLIC);
        RSAKey.Builder keyBuilder = new RSAKey.Builder((RSAPublicKey) publicKey);
        return keyBuilder.build();
    }

    public String encrypt(Authentication authentication, String data) {
        E2EKey e2EKey = findOrGenerateKeyPair(authentication);
        PublicKey publicKey = (PublicKey) unwrapKey(e2EKey.getCurrentPublicKey(), e2EKey.getCreationDate(), PUBLIC);
        return RsaEncryptorBuilder.client(publicKey).encrypt(data);
    }

    public String decrypt(Authentication authentication, String data) {
        E2EKey e2EKey = findOrGenerateKeyPair(authentication);
        PrivateKey privateKey = (PrivateKey) unwrapKey(e2EKey.getCurrentPrivateKey(), e2EKey.getCreationDate(), PRIVATE);
        return RsaEncryptorBuilder.server(privateKey).decrypt(data);
    }

    private E2EKey findOrGenerateKeyPair(Authentication authentication) {
        String association = findAssociation(authentication);
        E2EKey.UserType userType = findUserType(authentication);
        E2EKey.KeyId keyId = new E2EKey.KeyId(association, userType);
        Optional<E2EKey> keyOptional = keyRepository.findById(keyId);
        if (keyOptional.isPresent() && keyOptional.get().isValid(identityProperties.getE2eKeyValidity())) {
            return keyOptional.get();
        } else {
            E2EKey keyEntry;
            if (keyOptional.isPresent()) {
                keyEntry = keyOptional.get();
                keyEntry.setOldPrivateKey(keyEntry.getCurrentPrivateKey());
                keyEntry.setOldPublicKey(keyEntry.getCurrentPrivateKey());
                return generateKeyPair(keyEntry);
            } else {
                keyEntry = generateKeyPair(association, userType);
                return keyRepository.saveAndFlush(keyEntry);
            }
        }
    }

    private E2EKey generateKeyPair(@NonNull E2EKey keyEntry) {
        try {
            LocalDateTime creationDate = LocalDateTime.now();
            KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
            keyEntry.setCurrentPrivateKey(wrapKey(keyPair.getPrivate(), creationDate));
            keyEntry.setCurrentPublicKey(wrapKey(keyPair.getPublic(), creationDate));
            keyEntry.setCreationDate(creationDate);
            return keyRepository.saveAndFlush(keyEntry);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private E2EKey generateKeyPair(String association, E2EKey.UserType userType) {
        E2EKey e2EKey = new E2EKey();
        e2EKey.setAssociation(association);
        e2EKey.setUserType(userType);
        return generateKeyPair(e2EKey);
    }

    private String wrapKey(Key key, LocalDateTime encryptionDate) {
        return encryptorFactory.createEncryptor(encryptionDate).wrapKey(key);
    }

    private Key unwrapKey(String encodedKey, LocalDateTime encryptionDate, int type) {
        return encryptorFactory.createEncryptor(encryptionDate).unwrapKey(encodedKey, "RSA", type);
    }

    private String findAssociation(Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()) {
            return null;
        }
        UserDetails principal = (UserDetails) authentication.getPrincipal();
        return principal.getUsername();
    }

    private E2EKey.UserType findUserType(Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()) {
            return null;
        }
        UserDetails principal = (UserDetails) authentication.getPrincipal();
        System.out.println(principal.getClass());
        if (principal instanceof User) {
            return E2EKey.UserType.USER;
        } else if (principal instanceof Client) {
            return E2EKey.UserType.CLIENT;
        } else if (principal instanceof Profile) {
            return ((Profile) principal).isClient() ? E2EKey.UserType.CLIENT : E2EKey.UserType.USER;
        }
        throw new RuntimeException("Could not determine User Type.");
    }
}
