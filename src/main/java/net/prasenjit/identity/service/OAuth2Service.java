package net.prasenjit.identity.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.prasenjit.identity.entity.AccessToken;
import net.prasenjit.identity.entity.Client;
import net.prasenjit.identity.entity.User;
import net.prasenjit.identity.exception.OAuthException;
import net.prasenjit.identity.model.OAuthToken;
import org.apache.commons.lang3.ArrayUtils;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;

@Slf4j
@Service
@RequiredArgsConstructor
public class OAuth2Service {

    private final AuthenticationManager authenticationManager;

    private final CodeFactory codeFactory;

    public OAuthToken processPasswordGrant(Client client, String username, String password, String scope) {
        if (!client.supportsGrant("password")) {
            throw new OAuthException("Unsupported grant");
        }
        Authentication authentication = new UsernamePasswordAuthenticationToken(username, password);
        try {
            authentication = authenticationManager.authenticate(authentication);
        } catch (BadCredentialsException e) {
            throw new OAuthException("user authentication failed");
        }
        if (authentication.isAuthenticated() && validateScope(scope, client.getApprovedScopes())) {
            AccessToken accessToken = codeFactory.createAccessToken((User) authentication.getPrincipal(),
                    client.getClientId(), client.getAccessTokenValidity(), scope);
            OAuthToken bearer = OAuthToken.builder().accessToken(accessToken.getAssessToken())
                    .tokenType("bearer")
                    .expiresIn(ChronoUnit.SECONDS.between(LocalDateTime.now(), accessToken.getExpiryDate()))
                    .build();
            return bearer;
        } else {
            throw new OAuthException("invalid scope");
        }
    }

    private boolean validateScope(String scope, String approvedScopes) {
        String[] requiredScopes = StringUtils.commaDelimitedListToStringArray(scope);
        final String[] availableScopes = StringUtils.commaDelimitedListToStringArray(approvedScopes);
        return Arrays.stream(requiredScopes).allMatch(r -> ArrayUtils.contains(availableScopes, r));
    }
}