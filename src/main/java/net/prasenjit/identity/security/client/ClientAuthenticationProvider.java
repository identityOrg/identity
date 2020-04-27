package net.prasenjit.identity.security.client;

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
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.auth.JWTAuthentication;
import com.nimbusds.oauth2.sdk.auth.PlainClientSecret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
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
public class ClientAuthenticationProvider implements AuthenticationProvider {
    private final ClientRepository clientRepository;
    private final MetadataService metadataService;
    private final RemoteResourceRetriever resourceRetriever;
    private final TextEncryptor textEncryptor;

    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        Assert.isInstanceOf(ClientAuthenticationToken.class, authentication,
                "Only BasicAuthenticationToken is supported");

        // Determine username
        String clientId = (authentication.getPrincipal() == null) ? "NONE_PROVIDED" : authentication.getName();
        Client client = clientRepository.findById(clientId).orElseThrow(() -> new BadCredentialsException("Bad credentials"));

        this.preAuthenticationCheck(client);
        additionalAuthenticationChecks(client, (ClientAuthenticationToken) authentication);

        return createSuccessAuthentication(client.getClientId(), authentication, Profile.create(client));
    }

    public boolean supports(Class<?> authentication) {
        return (ClientAuthenticationToken.class.isAssignableFrom(authentication));
    }

    private Authentication createSuccessAuthentication(Object principal, Authentication authentication,
                                                       UserDetails user) {
        ClientAuthenticationToken result = new ClientAuthenticationToken(principal,
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

    private void additionalAuthenticationChecks(Client client, ClientAuthenticationToken authentication)
            throws AuthenticationException {
        if (authentication.getCredentials() == null) {
            log.debug("Authentication failed: no credentials provided");
            throw new BadCredentialsException("Bad credentials");
        }

        ClientAuthentication credentials = (ClientAuthentication) authentication.getCredentials();
        ClientID clientID = (ClientID) authentication.getPrincipal();

        validateClientAuthentication(client, clientID, credentials);
    }

    private void validateClientAuthentication(Client client, ClientID clientID, ClientAuthentication clientAuthentication) {
        if (!clientAuthentication.getClientID().equals(clientID)) {
            log.debug("Authentication failed: client is mismatch");
            throw new BadCredentialsException("Bad credentials");
        }
        ClientAuthenticationMethod receivedAuthMethod = clientAuthentication.getMethod();
        if (client.getClientSecret() == null) {
            if (ClientAuthenticationMethod.NONE.equals(receivedAuthMethod)) {
                return; // insecure client is authenticated when method is none
            } else {
                log.debug("Insecure client can not be authenticated with {}", receivedAuthMethod.getValue());
                throw new BadCredentialsException("Bad credentials");
            }
        }
        ClientAuthenticationMethod registeredAuthMethod = client.getMetadata().getTokenEndpointAuthMethod();
        if (receivedAuthMethod.equals(registeredAuthMethod)
                || (registeredAuthMethod == null && clientAuthentication instanceof PlainClientSecret)) {
            // allow to authenticate even if no method registered but requested plain authentication
            if (clientAuthentication instanceof PlainClientSecret) {
                PlainClientSecret plainClientSecret = (PlainClientSecret) clientAuthentication;
                performSimpleAuthentication(client, plainClientSecret);
            } else if (clientAuthentication instanceof JWTAuthentication) {
                JWTAuthentication jwtAuthentication = (JWTAuthentication) clientAuthentication;
                performJwtAuthentication(client, jwtAuthentication);
            } else {
                log.debug("Authentication method {} not supported.", clientAuthentication.getMethod().getValue());
                throw new BadCredentialsException("Bad credentials");
            }
        } else {
            log.debug("Authentication method doesnt match with registered method.");
            throw new BadCredentialsException("Bad credentials");
        }
    }

    private void performSimpleAuthentication(Client client, PlainClientSecret plainClientSecret) {
        String savedSecret = client.getClientSecret();
        String providedSecret = plainClientSecret.getClientSecret().getValue();
        if (!textEncryptor.decrypt(savedSecret).contentEquals(providedSecret)) {
            log.debug("Authentication failed: password does not match stored value");
            throw new BadCredentialsException("Bad credentials");
        }
    }

    private void performJwtAuthentication(Client client, JWTAuthentication jwtAuthentication) {
        JWSAlgorithm expectedSigningAlgorithm = client.getMetadata().getTokenEndpointAuthJWSAlg();
        if (expectedSigningAlgorithm == null) {
            log.debug("Authentication failed: signing algorithm not registered");
            throw new BadCredentialsException("Bad credentials");
        }
        Set<String> acceptableAudience = findAudiences();

        ConfigurableJWTProcessor<SimpleSecurityContext> processor = new DefaultJWTProcessor<>();
        JWKSource<SimpleSecurityContext> keySource = findKeySource(client, jwtAuthentication);
        JWSVerificationKeySelector<SimpleSecurityContext> jwsKeySelector =
                new JWSVerificationKeySelector<>(expectedSigningAlgorithm, keySource);
        processor.setJWSKeySelector(jwsKeySelector);
        JWTClaimsSet claimMatcher = new JWTClaimsSet.Builder()
                .subject(jwtAuthentication.getClientID().getValue())
                .issuer(jwtAuthentication.getClientID().getValue())
                .build();
        Set<String> requiredClaims = new HashSet<>();
        requiredClaims.add("exp");
        requiredClaims.add("jti");
        DefaultJWTClaimsVerifier<SimpleSecurityContext> claimsVerifier = new DefaultJWTClaimsVerifier<>(
                acceptableAudience, claimMatcher, requiredClaims, null);
        processor.setJWTClaimsSetVerifier(claimsVerifier);

        try {
            processor.process(jwtAuthentication.getClientAssertion(), new SimpleSecurityContext());
        } catch (BadJOSEException | JOSEException e) {
            log.debug("Authentication failed: credential verification failed", e);
            throw new BadCredentialsException("Bad credentials", e);
        }
    }

    private Set<String> findAudiences() {
        HashSet<String> audiences = new HashSet<>();
        OIDCProviderMetadata oidcConfiguration = metadataService.findOIDCConfiguration();
        audiences.add(oidcConfiguration.getTokenEndpointURI().toString());
        audiences.add(oidcConfiguration.getIntrospectionEndpointURI().toString());
        audiences.add(oidcConfiguration.getRevocationEndpointURI().toString());
//        audiences.add(oidcConfiguration.getEndSessionEndpointURI().toString());
        return audiences;
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
