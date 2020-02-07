package net.prasenjit.identity.security.jwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.ImmutableSecret;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SimpleSecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.auth.JWTAuthentication;
import com.nimbusds.oauth2.sdk.id.ClientID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.prasenjit.crypto.TextEncryptor;
import net.prasenjit.identity.entity.client.Client;
import net.prasenjit.identity.model.Profile;
import net.prasenjit.identity.repository.ClientRepository;
import net.prasenjit.identity.service.RemoteResourceRetriever;
import net.prasenjit.identity.service.openid.MetadataService;
import org.springframework.security.authentication.AccountExpiredException;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.Assert;

import java.net.MalformedURLException;
import java.util.HashSet;
import java.util.Set;

@Slf4j
@RequiredArgsConstructor
public class JWTClientAuthenticationProvider implements AuthenticationProvider {
    private final ClientRepository clientRepository;
    private final MetadataService metadataService;
    private final RemoteResourceRetriever resourceRetriever;
    private final TextEncryptor textEncryptor;

    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        Assert.isInstanceOf(JWTClientAuthenticationToken.class, authentication,
                "Only BasicAuthenticationToken is supported");

        // Determine username
        String clientId = (authentication.getPrincipal() == null) ? "NONE_PROVIDED" : authentication.getName();
        Client client = clientRepository.findById(clientId).orElseThrow(() -> new BadCredentialsException("Bad credentials"));

        this.preAuthenticationCheck(client);
        additionalAuthenticationChecks(client, (JWTClientAuthenticationToken) authentication);

        return createSuccessAuthentication(client.getClientId(), authentication, Profile.create(client));
    }

    public boolean supports(Class<?> authentication) {
        return (JWTClientAuthenticationToken.class.isAssignableFrom(authentication));
    }

    private Authentication createSuccessAuthentication(Object principal, Authentication authentication,
                                                       UserDetails user) {
        JWTClientAuthenticationToken result = new JWTClientAuthenticationToken(principal,
                authentication.getCredentials(), user.getAuthorities());

        result.setDetails(authentication.getDetails());
        return result;
    }

    private void preAuthenticationCheck(Client client) {
        if (!client.isAccountNonExpired()) {
            log.debug("User account is expired");
            throw new AccountExpiredException("User account has expired");
        }
    }

    private void additionalAuthenticationChecks(Client client, JWTClientAuthenticationToken authentication)
            throws AuthenticationException {
        if (authentication.getCredentials() == null) {
            log.debug("Authentication failed: no credentials provided");
            throw new BadCredentialsException("Bad credentials");
        }

        JWTAuthentication credentials = (JWTAuthentication) authentication.getCredentials();
        ClientID clientID = (ClientID) authentication.getPrincipal();

        validateClientJWT(client, clientID, credentials);
    }

    private void validateClientJWT(Client client, ClientID clientID, JWTAuthentication clientSecretJWT) {
        if (!clientSecretJWT.getClientID().equals(clientID)) {
            log.debug("Authentication failed: client is mismatch");
            throw new BadCredentialsException("Bad credentials");
        }
        JWSAlgorithm expectedSigningAlgorithm = client.getMetadata().getTokenEndpointAuthJWSAlg();
        if (expectedSigningAlgorithm == null) {
            log.debug("Authentication failed: signing algorithm not registered");
            throw new BadCredentialsException("Bad credentials");
        }
        if (client.getClientSecret() == null && clientSecretJWT.getMethod().equals(ClientAuthenticationMethod.CLIENT_SECRET_JWT)) {
            log.debug("Authentication failed: insecure client can not use method {}", ClientAuthenticationMethod.CLIENT_SECRET_JWT);
        }
        String tokenEP = metadataService.findOIDCConfiguration().getTokenEndpointURI().toString();

        ConfigurableJWTProcessor<SimpleSecurityContext> processor = new DefaultJWTProcessor<>();
        JWKSource<SimpleSecurityContext> keySource = findKeySource(client, clientSecretJWT);
        JWSVerificationKeySelector<SimpleSecurityContext> jwsKeySelector =
                new JWSVerificationKeySelector<>(expectedSigningAlgorithm, keySource);
        processor.setJWSKeySelector(jwsKeySelector);
        JWTClaimsSet claimMatcher = new JWTClaimsSet.Builder()
                .subject(clientID.getValue())
                .issuer(clientID.getValue())
                .build();
        Set<String> requiredClaims = new HashSet<>();
        requiredClaims.add("exp");
        requiredClaims.add("jti");
        DefaultJWTClaimsVerifier<SimpleSecurityContext> claimsVerifier = new DefaultJWTClaimsVerifier<>(tokenEP, claimMatcher, requiredClaims);
        processor.setJWTClaimsSetVerifier(claimsVerifier);

        try {
            processor.process(clientSecretJWT.getClientAssertion(), new SimpleSecurityContext());
        } catch (BadJOSEException | JOSEException e) {
            log.debug("Authentication failed: credential verification failed", e);
            throw new BadCredentialsException("Bad credentials", e);
        }
    }

    private JWKSource<SimpleSecurityContext> findKeySource(Client client, JWTAuthentication authentication) {
        if (authentication.getMethod().equals(ClientAuthenticationMethod.PRIVATE_KEY_JWT)) {
            if (client.getMetadata().getJWKSet() != null) {
                return new ImmutableJWKSet<>(client.getMetadata().getJWKSet());
            } else if (client.getMetadata().getJWKSetURI() != null) {
                try {
                    new RemoteJWKSet<SimpleSecurityContext>(client.getMetadata().getJWKSetURI().toURL(), resourceRetriever);
                } catch (MalformedURLException e) {
                    log.debug("Authentication failed: remote key retrieval failed", e);
                    throw new BadCredentialsException("Bad credentials", e);
                }
            }
        } else if (authentication.getMethod().equals(ClientAuthenticationMethod.CLIENT_SECRET_JWT)) {
            String decryptedSecret = textEncryptor.decrypt(client.getClientSecret());
            return new ImmutableSecret<>(decryptedSecret.getBytes());
        }
        log.debug("Authentication failed: nondeterministic key source");
        throw new BadCredentialsException("Bad credentials");
    }
}
