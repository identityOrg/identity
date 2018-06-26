package net.prasenjit.identity.config;

import lombok.RequiredArgsConstructor;
import net.prasenjit.crypto.TextEncryptor;
import net.prasenjit.identity.oauth.BasicAuthenticationProvider;
import net.prasenjit.identity.oauth.BearerAuthenticationProvider;
import net.prasenjit.identity.repository.AccessTokenRepository;
import net.prasenjit.identity.service.ClientService;
import net.prasenjit.identity.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.*;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
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

    @Autowired
    @Qualifier("client-password")
    public TextEncryptor textEncryptor;

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationEventPublisher eventPublisher) {
        List<AuthenticationProvider> providers = new ArrayList<>();
        providers.add(userAuthProvider());
        providers.add(bearerAuthProvider());
        providers.add(clientAuthProvider());
        ProviderManager providerManager = new ProviderManager(providers);
        providerManager.setAuthenticationEventPublisher(eventPublisher);
        providerManager.setEraseCredentialsAfterAuthentication(true);
        return providerManager;
    }

    @Bean
    public DefaultAuthenticationEventPublisher eventPublisher() {
        return new DefaultAuthenticationEventPublisher();
    }

    private AuthenticationProvider userAuthProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(PasswordEncoderFactories.createDelegatingPasswordEncoder());
        provider.setUserDetailsService(userService);
        return provider;
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
                return textEncryptor.decrypt(encodedPassword).equals(rawPassword);
            }

            @Override
            public String encode(CharSequence rawPassword) {
                return textEncryptor.encrypt(rawPassword.toString());
            }
        };
    }
}
