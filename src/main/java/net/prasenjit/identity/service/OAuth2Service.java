package net.prasenjit.identity.service;

import lombok.RequiredArgsConstructor;
import net.prasenjit.identity.entity.AccessToken;
import net.prasenjit.identity.entity.AuthorizationCode;
import net.prasenjit.identity.entity.RefreshToken;
import net.prasenjit.identity.entity.User;
import net.prasenjit.identity.entity.client.Client;
import net.prasenjit.identity.exception.OAuthException;
import net.prasenjit.identity.exception.UnauthenticatedClientException;
import net.prasenjit.identity.model.AuthorizationModel;
import net.prasenjit.identity.model.OAuthToken;
import net.prasenjit.identity.model.Profile;
import net.prasenjit.identity.repository.AuthorizationCodeRepository;
import net.prasenjit.identity.repository.ClientRepository;
import net.prasenjit.identity.repository.RefreshTokenRepository;
import net.prasenjit.identity.repository.UserRepository;
import net.prasenjit.identity.security.GrantType;
import net.prasenjit.identity.security.OAuthError;
import net.prasenjit.identity.security.user.UserAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

//@Slf4j
@Service
@RequiredArgsConstructor
public class OAuth2Service {

    private final AuthenticationManager authenticationManager;
    private final CodeFactory codeFactory;
    private final ClientRepository clientRepository;
    private final AuthorizationCodeRepository codeRepository;
    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;

    public OAuthToken processPasswordGrant(Profile profile, String username, String password, String requestedScope) {
        Client client = clientRepository.getOne(profile.getUsername());
        if (!client.supportsGrant(GrantType.PASSWORD)) {
            throw new OAuthException("invalid_grant", "Unsupported grant");
        }
        Authentication authentication = new UserAuthenticationToken(username, password);
        try {
            authentication = authenticationManager.authenticate(authentication);
        } catch (BadCredentialsException e) {
            throw new OAuthException("access_denied", "user authentication failed", e);
        }
        String filteredScopes = filterScope(client.getApprovedScopes(), requestedScope);
        AccessToken accessToken = codeFactory.createAccessToken((Profile) authentication.getPrincipal(),
                client.getClientId(), client.getAccessTokenValidity(), filteredScopes, LocalDateTime.now());
        RefreshToken refreshToken = null;
        if (!client.supportsGrant(GrantType.REFRESH_TOKEN)) {
            refreshToken = codeFactory.createRefreshToken(client.getClientId(), username, filteredScopes,
                    LocalDateTime.now(), client.getRefreshTokenValidity(), false);
        }
        return codeFactory.createOAuthToken(accessToken, refreshToken, null);
    }

    public OAuthToken processClientCredentialsGrant(Profile profile, String scope) {
        Optional<Client> clientOptional = clientRepository.findById(profile.getUsername());
        if (!clientOptional.isPresent()) {
            throw new OAuthException(OAuthError.INVALID_REQUEST, "Client not found");
        }
        Client client = clientOptional.get();
        if (!client.supportsGrant(GrantType.CLIENT_CREDENTIALS)) {
            throw new OAuthException("invalid_grant", "Unsupported grant");
        }
        String filteredScope = filterScope(client.getApprovedScopes(), scope);
        AccessToken accessToken = codeFactory.createAccessToken(Profile.create(client), client.getClientId(),
                client.getAccessTokenValidity(), filteredScope, LocalDateTime.now());
        return codeFactory.createOAuthToken(accessToken, null, null);
    }

    public OAuthToken processAuthorizationCodeGrantToken(Profile profile, String code, String redirectUri,
                                                         String clientId) {
        Client client;
        if (profile == null) {
            if (clientId == null) {
                throw new OAuthException("invalid_request", "non secure client must specify client_id parameter");
            }
            Optional<Client> optionalClient = clientRepository.findById(clientId);
            if (optionalClient.isPresent()) {
                if (optionalClient.get().supportsGrant(GrantType.AUTHORIZATION_CODE)) {
                    throw new UnauthenticatedClientException("unauthorized_client", "Secure client must be authenticated");
                } else {
                    client = optionalClient.get();
                }
            } else {
                throw new OAuthException("invalid_request", "Client not found for client_id " + clientId);
            }
        } else {
            client = clientRepository.findById(profile.getUsername()).get();
        }
        if (null == code) {
            throw new OAuthException("invalid_request", "authorization code must be provided");
        } else {
            Optional<AuthorizationCode> authorizationCode = codeRepository.findByAuthorizationCode(code);
            if (authorizationCode.isPresent()) {
                if (!authorizationCode.get().isUsed()) {
                    if (authorizationCode.get().getClientId().equals(client.getClientId())) {
                        if (!StringUtils.hasText(authorizationCode.get().getReturnUrl())
                                || authorizationCode.get().getReturnUrl().equals(redirectUri)) {
                            if (authorizationCode.get().isValid()) {
                                authorizationCode.get().setUsed(true);
                                Optional<User> associatedUser = userRepository
                                        .findById(authorizationCode.get().getUsername());
                                if (associatedUser.isPresent()) {
                                    AccessToken accessToken = codeFactory.createAccessToken(
                                            Profile.create(associatedUser.get()),
                                            client.getClientId(), client.getAccessTokenValidity(),
                                            authorizationCode.get().getScope(),
                                            authorizationCode.get().getLoginDate());
                                    String idToken = null;
                                    if (authorizationCode.get().isOpenId()) {
                                        String[] strings = StringUtils.delimitedListToStringArray(
                                                authorizationCode.get().getScope(), " ");
                                        idToken = codeFactory.createIDToken(Profile.create(associatedUser.get()),
                                                authorizationCode.get().getLoginDate(), null,
                                                client.getClientId(), client.getAccessTokenValidity(),
                                                CollectionUtils.arrayToList(strings), accessToken.getAssessToken(),
                                                null);
                                    }
                                    RefreshToken refreshToken = null;
                                    if (client.supportsGrant(GrantType.REFRESH_TOKEN)) {
                                        refreshToken = codeFactory.createRefreshToken(client.getClientId(),
                                                associatedUser.get().getUsername(),
                                                accessToken.getScope(), authorizationCode.get().getLoginDate(),
                                                client.getRefreshTokenValidity(), authorizationCode.get().isOpenId());
                                    }
                                    return codeFactory.createOAuthToken(accessToken, refreshToken, idToken);
                                }
                            }
                        }
                    }
                }
            }
            throw new OAuthException("invalid_request", "Authorization code invalid");
        }
    }

    public OAuthToken processRefreshTokenGrantToken(Client client, String refreshToken) {
        if (client == null) {
            throw new UnauthenticatedClientException("unauthorized_client", "Client is not authenticated");
        }
        Optional<RefreshToken> tokenOptional = refreshTokenRepository.findById(refreshToken);
        if (tokenOptional.isPresent()) {
            if (tokenOptional.get().isValid()) {
                Optional<User> userOptional = userRepository.findById(tokenOptional.get().getUsername());
                if (userOptional.isPresent()) {
                    if (userOptional.get().isValid()) {
                        tokenOptional.get().setUsed(true);
                        AccessToken accessToken = codeFactory.createAccessToken(Profile.create(userOptional.get()),
                                client.getClientId(), client.getAccessTokenValidity(), tokenOptional.get().getScope(),
                                tokenOptional.get().getLoginDate());
                        RefreshToken refreshToken1 = codeFactory.createRefreshToken(client.getClientId(),
                                userOptional.get().getUsername(), tokenOptional.get().getScope(),
                                tokenOptional.get().getLoginDate(), client.getRefreshTokenValidity(),
                                tokenOptional.get().isOpenId());
                        return codeFactory.createOAuthToken(accessToken, refreshToken1, null); // TODO add id token from refresh token
                    } else {
                        throw new UnauthenticatedClientException("access_denied", "Invalid user");
                    }
                } else {
                    throw new OAuthException("access_denied", "Associated user not found");
                }
            } else {
                throw new OAuthException("access_denied", "Expired refresh token");
            }
        }
        throw new OAuthException("access_denied", "Invalid refresh token");
    }

    public String createTokenResponseFragment(Map<String, String> respMap) {
        String fragment = respMap.entrySet().stream()
                .map(e -> e.getKey() + "=" + e.getValue())
                .reduce((s, s2) -> s + "&" + s2).orElse("");
        return fragment;
    }

    private void filterScopeToMap(String approvedScopes, String requestedScope,
                                  AuthorizationModel authorizationModel) {
        String[] approved = StringUtils.delimitedListToStringArray(approvedScopes, " ");
        String[] requested = StringUtils.delimitedListToStringArray(requestedScope, " ");
        if (approved.length == 0) {
            return;
        }
        if (requested.length == 0) {
            authorizationModel.setFilteredScopes(Stream.of(approved)
                    .collect(Collectors.toMap(o -> o, o -> Boolean.TRUE)));
            return;
        }
        Arrays.sort(approved);
        Arrays.sort(requested);
        if (Arrays.binarySearch(requested, "openid") > -1) {
            authorizationModel.setOpenid(true);
        }
        for (String r : requested) {
            if (Arrays.binarySearch(approved, r) > -1) {
                authorizationModel.getFilteredScopes().put(r, Boolean.TRUE);
            }
        }
    }

    private String filterScope(String approvedScopes, String requestedScope) {
        String[] approved = StringUtils.delimitedListToStringArray(approvedScopes, " ");
        String[] requested = StringUtils.delimitedListToStringArray(requestedScope, " ");
        if (approved.length == 0) {
            return null;
        }
        if (requested.length == 0) {
            return approvedScopes;
        }
        Arrays.sort(approved);
        Arrays.sort(requested);
        List<String> filtered = new ArrayList<>();
        for (String r : requested) {
            if (Arrays.binarySearch(approved, r) > -1) {
                filtered.add(r);
            }
        }
        return StringUtils.collectionToDelimitedString(filtered, " ");
    }

    @SuppressWarnings("unchecked")
    private <T> T extractPrincipal(Authentication authentication, Class<T> userClass) {
        if (authentication != null && authentication.isAuthenticated()) {
            Object principal = authentication.getPrincipal();
            if (principal != null && userClass.isInstance(principal)) {
                return (T) principal;
            }
        }
        return null;
    }
}