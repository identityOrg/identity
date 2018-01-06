package net.prasenjit.identity.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.prasenjit.identity.entity.AccessToken;
import net.prasenjit.identity.entity.Client;
import net.prasenjit.identity.entity.RefreshToken;
import net.prasenjit.identity.entity.User;
import net.prasenjit.identity.exception.OAuthException;
import net.prasenjit.identity.model.AuthorizationModel;
import net.prasenjit.identity.model.OAuthToken;
import net.prasenjit.identity.repository.ClientRepository;
import org.apache.commons.lang3.ArrayUtils;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Slf4j
@Service
@RequiredArgsConstructor
public class OAuth2Service {

    private final AuthenticationManager authenticationManager;
    private final CodeFactory codeFactory;
    private final ClientRepository clientRepository;

    public OAuthToken processPasswordGrant(Client client, String username, String password, String requestedScope) {
        if (!client.supportsGrant("password")) {
            throw new OAuthException("Unsupported grant");
        }
        Authentication authentication = new UsernamePasswordAuthenticationToken(username, password);
        try {
            authentication = authenticationManager.authenticate(authentication);
        } catch (BadCredentialsException e) {
            throw new OAuthException("user authentication failed");
        }
        String filteredScopes = filterScope(client.getApprovedScopes(), requestedScope);
        AccessToken accessToken = codeFactory.createAccessToken((User) authentication.getPrincipal(),
                client.getClientId(), client.getAccessTokenValidity(), filteredScopes);
        OAuthToken.OAuthTokenBuilder tokenBuilder = OAuthToken.builder().accessToken(accessToken.getAssessToken())
                .tokenType("bearer")
                .expiresIn(ChronoUnit.SECONDS.between(LocalDateTime.now(), accessToken.getExpiryDate()))
                .scope(filteredScopes);
        if (!client.supportsGrant("refresh_token")) {
            RefreshToken refreshToken = codeFactory.createRefreshToken(client.getClientId(), username, filteredScopes,
                    client.getRefreshTokenValidity());
            tokenBuilder.refreshToken(refreshToken.getRefreshToken());
        }
        return tokenBuilder.build();
    }

    public OAuthToken processClientCredentialsGrant(Client client, String scope) {
        if (!client.supportsGrant("client_credentials")) {
            throw new OAuthException("Unsupported grant");
        }
        String filteredScope = filterScope(client.getApprovedScopes(), scope);
        AccessToken accessToken = codeFactory.createAccessToken(client,
                client.getClientId(), client.getAccessTokenValidity(), filteredScope);
        OAuthToken bearer = OAuthToken.builder().accessToken(accessToken.getAssessToken())
                .tokenType("bearer")
                .expiresIn(ChronoUnit.SECONDS.between(LocalDateTime.now(), accessToken.getExpiryDate()))
                .scope(filteredScope)
                .build();
        return bearer;
    }

//    public MultiValueMap<String, String> processAuthorizationCodeGrant(String clientId, User user) {
//        MultiValueMap<String, String> result = new LinkedMultiValueMap<>();
//        Optional<Client> optionalClient = clientRepository.findById(clientId);
//        if (!optionalClient.isPresent()) {
//            result.add("error", "invalid_client");
//            return result;
//        }
//        Client client = optionalClient.get();
//        if (!client.supportsGrant("password")) {
//            result.add("error", "unsupported_grant");
//            return result;
//        }
//    }

    public AuthorizationModel validateAuthorizationGrant(String responseType, User principal, String clientId,
                                                         String scope, String state, String redirectUri) {
        Optional<Client> client = clientRepository.findById(clientId);
        if (!client.isPresent()) {
            AuthorizationModel authorizationModel = new AuthorizationModel();
            authorizationModel.setValid(false);
            authorizationModel.setCode(OAuthError.INVALID_REQUEST);
            authorizationModel.setState(state);
            return authorizationModel;
        }
        if (redirectUri != null && !client.get().getRedirectUri().equals(redirectUri)) {
            AuthorizationModel authorizationModel = new AuthorizationModel();
            authorizationModel.setValid(false);
            authorizationModel.setCode(OAuthError.INVALID_REQUEST);
            authorizationModel.setState(state);
            return authorizationModel;
        }
        if ("code".equals(responseType)) {
            if (!client.get().supportsGrant("authorization_code")) {
                AuthorizationModel authorizationModel = new AuthorizationModel();
                authorizationModel.setValid(false);
                authorizationModel.setCode(OAuthError.ACCESS_DENIED);
                authorizationModel.setState(state);
                return authorizationModel;
            }
            Map<String, Boolean> scopeToApprove = filterScopeToMap(client.get().getApprovedScopes(), scope);

            AuthorizationModel authorizationModel = new AuthorizationModel();
            authorizationModel.setClient(client.get());
            authorizationModel.setUser(principal);
            authorizationModel.setRedirectUri(client.get().getRedirectUri());
            authorizationModel.setFilteredScopes(scopeToApprove);
            authorizationModel.setValid(true);
            authorizationModel.setCode(OAuthError.INVALID_REQUEST);
            authorizationModel.setState(state);
            return authorizationModel;
        } else if ("token".equals(responseType)) {
            AuthorizationModel authorizationModel = new AuthorizationModel();
            authorizationModel.setValid(false);
            authorizationModel.setCode(OAuthError.TEMPORARILY_UNAVAILABLE);
            authorizationModel.setState(state);
            return authorizationModel;
        } else {
            AuthorizationModel authorizationModel = new AuthorizationModel();
            authorizationModel.setValid(false);
            authorizationModel.setCode(OAuthError.INVALID_REQUEST);
            authorizationModel.setState(state);
            return authorizationModel;
        }
    }

    private Map<String, Boolean> filterScopeToMap(String approvedScopes, String requestedScope) {
        String[] approved = StringUtils.delimitedListToStringArray(approvedScopes, " ");
        String[] requested = StringUtils.delimitedListToStringArray(requestedScope, " ");
        if (approved == null || approved.length == 0) {
            return new HashMap<>();
        }
        if (requested == null || requested.length == 0) {
            return Stream.of(approved).collect(Collectors.toMap(o -> o, o -> Boolean.TRUE));
        }
        Map<String, Boolean> filteredMap = new HashMap<>();
        for (String r : requested) {
            if (ArrayUtils.contains(approved, r)) {
                filteredMap.put(r, Boolean.TRUE);
            }
        }
        return filteredMap;
    }

    private String filterScope(String approvedScopes, String requestedScope) {
        String[] approved = StringUtils.delimitedListToStringArray(approvedScopes, " ");
        String[] requested = StringUtils.delimitedListToStringArray(requestedScope, " ");
        if (approved == null || approved.length == 0) {
            return null;
        }
        if (requested == null || requested.length == 0) {
            return approvedScopes;
        }
        List<String> filtered = new ArrayList<>();
        for (String r : requested) {
            if (ArrayUtils.contains(approved, r)) {
                filtered.add(r);
            }
        }
        return StringUtils.collectionToDelimitedString(filtered, " ");
    }
}