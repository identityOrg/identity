package net.prasenjit.identity.config;

import lombok.RequiredArgsConstructor;
import net.prasenjit.identity.oauth.BearerAuthenticationProvider;
import net.prasenjit.identity.repository.AccessTokenRepository;
import net.prasenjit.identity.service.ClientService;
import net.prasenjit.identity.service.UserService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;

import java.util.ArrayList;
import java.util.List;

@Configuration
@RequiredArgsConstructor
public class AuthManagerConfig {

    private final UserService userService;
    private final ClientService clientService;
    private final AccessTokenRepository accessTokenRepository;

    @Bean
    public AuthenticationManager authenticationManager() {
        List<AuthenticationProvider> providers = new ArrayList<>();
        providers.add(userAuthProvider());
        providers.add(bearerAuthProvider());
        providers.add(clientAuthProvider());
        ProviderManager providerManager = new ProviderManager(providers);
        providerManager.setEraseCredentialsAfterAuthentication(true);
        return providerManager;
    }

    private AuthenticationProvider userAuthProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(PasswordEncoderFactories.createDelegatingPasswordEncoder());
        provider.setUserDetailsService(userService);
        return provider;
    }

    private AuthenticationProvider clientAuthProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(NoOpPasswordEncoder.getInstance());
        provider.setUserDetailsService(clientService);
        return provider;
    }

    private AuthenticationProvider bearerAuthProvider() {
        BearerAuthenticationProvider provider = new BearerAuthenticationProvider(accessTokenRepository);
        return provider;
    }
}
