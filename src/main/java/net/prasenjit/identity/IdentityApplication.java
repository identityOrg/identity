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

package net.prasenjit.identity;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.openid.connect.sdk.claims.Address;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import com.nimbusds.openid.connect.sdk.rp.ApplicationType;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;
import lombok.extern.slf4j.Slf4j;
import net.prasenjit.crypto.TextEncryptor;
import net.prasenjit.identity.entity.Status;
import net.prasenjit.identity.entity.client.Client;
import net.prasenjit.identity.entity.scope.ScopeEntity;
import net.prasenjit.identity.entity.user.User;
import net.prasenjit.identity.repository.ClientRepository;
import net.prasenjit.identity.repository.ScopeRepository;
import net.prasenjit.identity.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.net.URI;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Slf4j
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

        if (userRepository.count() > 0) return;

        log.info("Creating default users");

        User admin = createAdmin("admin");
        userRepository.saveAndFlush(admin);

        admin = createAdmin("user");
        userRepository.saveAndFlush(admin);

        if (clientRepository.count() > 0) return;

        log.info("Creating default clients");

        Client client = createClient("client", true);
        clientRepository.saveAndFlush(client);

        client = createClient("insecure", false);
        clientRepository.saveAndFlush(client);

    }

    private Client createClient(String clientId, boolean secure) throws JOSEException, ParseException {
        Client client = new Client();
        client.setClientId(clientId);
        if (secure)
            client.setClientSecret(textEncryptor.encrypt(clientId));
        client.setCreationDate(LocalDateTime.now());
        client.setStatus(Status.ACTIVE);
        client.setClientName("Test Client");
        final OIDCClientMetadata metadata = new OIDCClientMetadata();
        client.setMetadata(metadata);
        scopeRepository.findAll().stream()
                .map(ScopeEntity::getScopeId)
                .reduce((x, y) -> x + " " + y)
                .map(Scope::parse)
                .ifPresent(metadata::setScope);
        metadata.setRedirectionURI(URI.create("http://localhost:4200/callback"));
        client.setAccessTokenValidity(Duration.ofMinutes(30));
        client.setRefreshTokenValidity(Duration.ofHours(2));
        metadata.setApplicationType(ApplicationType.getDefault());
        metadata.setGrantTypes(getAllGrantTypes());
        metadata.setResponseTypes(getAllResponseTypes());
        metadata.setJWKSet(createRandomJwks());
        metadata.setRequestObjectJWEAlg(JWEAlgorithm.RSA_OAEP_256);
        metadata.setRequestObjectJWSAlg(JWSAlgorithm.RS256);
        metadata.setRequestObjectJWEEnc(EncryptionMethod.A128GCM);
        return client;
    }

    private Set<ResponseType> getAllResponseTypes() throws ParseException {
        HashSet<ResponseType> responseTypes = new HashSet<>();
        responseTypes.add(ResponseType.parse("code"));
        responseTypes.add(ResponseType.parse("id_token"));
        responseTypes.add(ResponseType.parse("id_token token"));
        responseTypes.add(ResponseType.parse("code id_token"));
        responseTypes.add(ResponseType.parse("code token"));
        responseTypes.add(ResponseType.parse("code id_token token"));
        return responseTypes;
    }

    private Set<GrantType> getAllGrantTypes() {
        Set<GrantType> grants = new HashSet<>();
        grants.add(GrantType.AUTHORIZATION_CODE);
        grants.add(GrantType.IMPLICIT);
        grants.add(GrantType.REFRESH_TOKEN);
        grants.add(GrantType.PASSWORD);
        grants.add(GrantType.CLIENT_CREDENTIALS);
        return grants;
    }

    private JWKSet createRandomJwks() throws JOSEException {
        List<JWK> keys = new ArrayList<>();
        RSAKeyGenerator generator = new RSAKeyGenerator(2048);
        generator.keyID("encr");
        generator.keyUse(KeyUse.ENCRYPTION);
        keys.add(generator.generate());
        generator = new RSAKeyGenerator(2048);
        generator.keyID("sign");
        generator.keyUse(KeyUse.SIGNATURE);
        keys.add(generator.generate());

        return new JWKSet(keys);
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
        user.setUserInfo(createClaims(username));
        return user;
    }

    private UserInfo createClaims(String username) {
        UserInfo userProfile = new UserInfo(new Subject(username));
        Address address = new Address();
        address.setCountry("India");
        userProfile.setAddress(address);
        userProfile.setBirthdate("1984-09-11");
        userProfile.setName("Admin");
        return userProfile;
    }
}
