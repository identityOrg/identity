package net.prasenjit.identity.security.jwt;

import com.nimbusds.jose.proc.SimpleSecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;

import java.util.Set;

public class ClientAuthenticationClaimsVerifier extends DefaultJWTClaimsVerifier<SimpleSecurityContext> {
    public ClientAuthenticationClaimsVerifier(String requiredAudience, JWTClaimsSet exactMatchClaims, Set<String> requiredClaims) {
        super(requiredAudience, exactMatchClaims, requiredClaims);
    }
}
