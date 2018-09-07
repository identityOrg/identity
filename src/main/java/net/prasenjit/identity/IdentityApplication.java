package net.prasenjit.identity;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import net.minidev.json.JSONStyle;
import net.prasenjit.crypto.TextEncryptor;
import net.prasenjit.identity.entity.*;
import net.prasenjit.identity.entity.client.Client;
import net.prasenjit.identity.entity.user.User;
import net.prasenjit.identity.entity.user.UserAddress;
import net.prasenjit.identity.entity.user.UserProfile;
import net.prasenjit.identity.model.openid.EncryptionAlgorithm;
import net.prasenjit.identity.model.openid.EncryptionEnc;
import net.prasenjit.identity.model.openid.SignatureAlgorithm;
import net.prasenjit.identity.model.openid.registration.ApplicationType;
import net.prasenjit.identity.repository.ClientRepository;
import net.prasenjit.identity.repository.ScopeRepository;
import net.prasenjit.identity.repository.UserRepository;
import net.prasenjit.identity.security.GrantType;
import net.prasenjit.identity.security.ResponseType;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Duration;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;

@EnableAsync
@SpringBootApplication
public class IdentityApplication implements ApplicationRunner {

    @Autowired
    @Qualifier("client-password")
    public TextEncryptor textEncryptor;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private ClientRepository clientRepository;
    private PasswordEncoder userPasswordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
    @Autowired
    private ScopeRepository scopeRepository;

    public static void main(String[] args) {
        SpringApplication.run(IdentityApplication.class, args);
    }

    @Override
    public void run(ApplicationArguments args) throws Exception {

        scopeRepository.save(new ScopeEntity("scope1", "Scope 1"));
        scopeRepository.save(new ScopeEntity("scope2", "Scope 2"));
        scopeRepository.save(new ScopeEntity("openid", "OpenID Scope"));
        scopeRepository.save(new ScopeEntity("profile", "OpenID Profile"));
        scopeRepository.save(new ScopeEntity("email", "OpenID Email"));
        scopeRepository.save(new ScopeEntity("address", "OpenID Address"));

        User admin = createAdmin("admin");
        userRepository.saveAndFlush(admin);

        admin = createAdmin("user");
        userRepository.saveAndFlush(admin);

        Client client = createClient("client", true);
        clientRepository.saveAndFlush(client);

        client = createClient("insecure", false);
        clientRepository.saveAndFlush(client);

    }

    private Client createClient(String clientId, boolean secure) throws JOSEException {
        Client client = new Client();
        client.setClientId(clientId);
        if (secure)
            client.setClientSecret(textEncryptor.encrypt(clientId));
        client.setCreationDate(LocalDateTime.now());
        client.setStatus(Status.ACTIVE);
        client.setClientName("Test Client");
        client.setScopes(new HashSet<>(scopeRepository.findAll()));
        client.setRedirectUris(new String[]{"http://localhost:4200/callback"});
        client.setAccessTokenValidity(Duration.ofMinutes(30));
        client.setRefreshTokenValidity(Duration.ofHours(2));
        client.setApplicationType(ApplicationType.WEB);
        client.setApprovedGrants(GrantType.values());
        client.setApprovedResponseTypes(ResponseType.values());
        client.setJwks(createRandomJwks());
        client.getSecurityContainer().setRequestObjectSigningAlgo(SignatureAlgorithm.RS256);
        client.getSecurityContainer().setRequestObjectEncryptionAlgo(EncryptionAlgorithm.RSA_OAEP_256);
        client.getSecurityContainer().setRequestObjectEncryptionEnc(EncryptionEnc.A128GCM);
        return client;
    }

    private String createRandomJwks() throws JOSEException {
        List<JWK> keys = new ArrayList<>();
        RSAKeyGenerator generator = new RSAKeyGenerator(2048);
        generator.keyID("encr");
        generator.keyUse(KeyUse.ENCRYPTION);
        keys.add(generator.generate());
        generator = new RSAKeyGenerator(2048);
        generator.keyID("sign");
        generator.keyUse(KeyUse.SIGNATURE);
        keys.add(generator.generate());

        JWKSet jwkSet = new JWKSet(keys);
        return jwkSet.toJSONObject(false).toJSONString();
    }

    private User createAdmin(String username) {
        User user = new User();
        user.setAdmin(true);
        user.setCreationDate(LocalDateTime.now());
        user.setUsername(username);
        user.setPassword(userPasswordEncoder.encode(username));
        user.setActive(true);
        user.setLocked(false);
        user.setPasswordExpiryDate(LocalDateTime.now().plusDays(1));
        user.setUserProfile(createClaims(username));
        return user;
    }

    private UserProfile createClaims(String username) {
        UserProfile userProfile = new UserProfile();
        userProfile.setSub(username);
        userProfile.setAddress(new UserAddress());
        userProfile.getAddress().setCountry("India");
        userProfile.setBirthdate(LocalDate.of(0, 11, 9));
        return userProfile;
    }
}
