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

package net.prasenjit.identity.config;

import lombok.RequiredArgsConstructor;
import net.prasenjit.crypto.TextEncryptor;
import net.prasenjit.identity.model.openid.OpenIDSessionContainer;
import net.prasenjit.identity.repository.AccessTokenRepository;
import net.prasenjit.identity.repository.ClientRepository;
import net.prasenjit.identity.security.basic.BasicAuthenticationProvider;
import net.prasenjit.identity.security.bearer.BearerAuthenticationProvider;
import net.prasenjit.identity.security.client.ClientAuthenticationProvider;
import net.prasenjit.identity.security.user.UserAuthenticationProvider;
import net.prasenjit.identity.service.ClientService;
import net.prasenjit.identity.service.RemoteResourceRetriever;
import net.prasenjit.identity.service.UserService;
import net.prasenjit.identity.service.openid.MetadataService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.*;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;
import java.util.List;

@Configuration
@RequiredArgsConstructor
public class AuthManagerConfig {
    private final UserService userService;
    private final ClientService clientService;
    private final AccessTokenRepository accessTokenRepository;
    private final ClientRepository clientRepository;
    private final MetadataService metadataService;
    private final RemoteResourceRetriever resourceRetriever;

    @Autowired
    @Qualifier("client-password")
    public TextEncryptor textEncryptor;

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationEventPublisher eventPublisher,
                                                       OpenIDSessionContainer sessionContainer) {
        List<AuthenticationProvider> providers = new ArrayList<>();
        providers.add(userAuthProvider(sessionContainer));
        providers.add(bearerAuthProvider());
        providers.add(clientAuthProvider());
        providers.add(clientJWTProvider());
        ProviderManager providerManager = new ProviderManager(providers);
        providerManager.setAuthenticationEventPublisher(eventPublisher);
        providerManager.setEraseCredentialsAfterAuthentication(true);
        return providerManager;
    }

    @Bean
    public DefaultAuthenticationEventPublisher eventPublisher() {
        return new DefaultAuthenticationEventPublisher();
    }

    private AuthenticationProvider userAuthProvider(OpenIDSessionContainer sessionContainer) {
        UserAuthenticationProvider provider = new UserAuthenticationProvider();
        provider.setPasswordEncoder(PasswordEncoderFactories.createDelegatingPasswordEncoder());
        provider.setUserDetailsService(userService);
        provider.setSessionContainer(sessionContainer);
        return provider;
    }

    private AuthenticationProvider clientJWTProvider() {
        return new ClientAuthenticationProvider(clientRepository, metadataService, resourceRetriever, textEncryptor);
    }

    private AuthenticationProvider clientAuthProvider() {
        return new BasicAuthenticationProvider(clientPasswordEncoder(), clientService);
    }

    private AuthenticationProvider bearerAuthProvider() {
        return new BearerAuthenticationProvider(accessTokenRepository);
    }

    private PasswordEncoder clientPasswordEncoder() {
        return new PasswordEncoder() {

            @Override
            public boolean matches(CharSequence rawPassword, String encodedPassword) {
                return textEncryptor.decrypt(encodedPassword).contentEquals(rawPassword);
            }

            @Override
            public String encode(CharSequence rawPassword) {
                return textEncryptor.encrypt(rawPassword.toString());
            }
        };
    }
}
