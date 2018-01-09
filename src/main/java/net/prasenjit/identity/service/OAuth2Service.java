package net.prasenjit.identity.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.prasenjit.identity.entity.*;
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

import java.time.Duration;
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
        AuthorizationModel authorizationModel = new AuthorizationModel();
        authorizationModel.setState(state);
        authorizationModel.setUser(principal);
        authorizationModel.setValid(false);
        authorizationModel.setResponseType(responseType);

        Optional<Client> client = clientRepository.findById(clientId);

        if (!client.isPresent()) {
            authorizationModel.setRedirectUri(redirectUri);
            authorizationModel.setErrorCode(OAuthError.INVALID_REQUEST);
            authorizationModel.setErrorDescription("Provided clientId is invalid");
            return authorizationModel;
        } else {
            authorizationModel.setClient(client.get());
            authorizationModel.setRedirectUri(client.get().getRedirectUri());

            if (redirectUri != null && !client.get().getRedirectUri().equals(redirectUri)) {
                authorizationModel.setErrorCode(OAuthError.INVALID_REQUEST);
                authorizationModel.setErrorDescription("Redirect URL doesn't match");
                return authorizationModel;
            } else {
                if ("code".equals(responseType)) {
                    if (!client.get().supportsGrant("authorization_code")) {
                        authorizationModel.setErrorCode(OAuthError.ACCESS_DENIED);
                        authorizationModel.setErrorDescription("Client is not authorized for the specifies response type");
                        return authorizationModel;
                    }
                    Map<String, Boolean> scopeToApprove = filterScopeToMap(client.get().getApprovedScopes(), scope);

                    authorizationModel.setClient(client.get());
                    authorizationModel.setUser(principal);
                    authorizationModel.setFilteredScopes(scopeToApprove);
                    authorizationModel.setValid(true);
                    return authorizationModel;
                } else if ("token".equals(responseType)) {
                    if (!client.get().supportsGrant("implicit")) {
                        authorizationModel.setErrorCode(OAuthError.ACCESS_DENIED);
                        authorizationModel.setErrorDescription("Client is not authorized for the specifies response type");
                        return authorizationModel;
                    }
                    Map<String, Boolean> scopeToApprove = filterScopeToMap(client.get().getApprovedScopes(), scope);

                    authorizationModel.setClient(client.get());
                    authorizationModel.setUser(principal);
                    authorizationModel.setFilteredScopes(scopeToApprove);
                    authorizationModel.setValid(true);
                    return authorizationModel;
                } else {
                    authorizationModel.setErrorCode(OAuthError.INVALID_REQUEST);
                    authorizationModel.setErrorDescription("Unsupported response type ");
                    return authorizationModel;
                }
            }
        }
    }

    public AuthorizationModel processAuthorizationOrImplicitGrant(AuthorizationModel authorizationModel) {
        if (authorizationModel.isValid()) {
            Optional<Client> client = clientRepository.findById(authorizationModel.getClient().getClientId());

            if (!client.isPresent()) {
                authorizationModel.setValid(false);
                authorizationModel.setErrorCode(OAuthError.INVALID_REQUEST);
                authorizationModel.setErrorDescription("Provided clientId is invalid");
                return authorizationModel;
            } else {
                authorizationModel.setClient(client.get());
                List<String> approvedScope = authorizationModel.getFilteredScopes().entrySet()
                        .stream().filter(e -> e.getValue()).map(e -> e.getKey())
                        .collect(Collectors.toList());
                if ("code".equals(authorizationModel.getResponseType())) {
                    AuthorizationCode authorizationCode = codeFactory.createAuthorizationCode(client.get().getClientId(),
                            authorizationModel.getRedirectUri(),
                            StringUtils.collectionToDelimitedString(approvedScope, " "),
                            authorizationModel.getUser().getUsername(), authorizationModel.getState(),
                            Duration.ofMinutes(10));
                    authorizationModel.setAuthorizationCode(authorizationCode);
                    return authorizationModel;
                } else if ("token".equals(authorizationModel.getResponseType())) {
                    AccessToken accessToken = codeFactory.createAccessToken(authorizationModel.getUser(), client.get().getClientId(),
                            client.get().getAccessTokenValidity(),
                            StringUtils.collectionToDelimitedString(approvedScope, " "));
                    authorizationModel.setAccessToken(accessToken);
                    return authorizationModel;
                }
            }
        }
        authorizationModel.setErrorCode(OAuthError.UNAUTHORIZED_REQUEST);
        authorizationModel.setErrorDescription("User has denied the access");
        authorizationModel.setValid(false);
        return authorizationModel;
    }


    public String createTokenResponseFragment(AccessToken accessToken, String state) {
        StringBuilder builder = new StringBuilder();
        long expIn = ChronoUnit.SECONDS.between(LocalDateTime.now(), accessToken.getExpiryDate());
        builder.append("access_token").append('=').append(accessToken.getAssessToken())
                .append("token_type").append('=').append("Bearer")
                .append("expires_in").append('=').append(expIn)
                .append("scope").append('=').append(accessToken.getScope())
                .append("state").append('=').append(state);
        return builder.toString();
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