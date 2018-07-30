package net.prasenjit.identity.service;

import lombok.RequiredArgsConstructor;
import net.prasenjit.identity.entity.*;
import net.prasenjit.identity.exception.OAuthException;
import net.prasenjit.identity.exception.UnauthenticatedClientException;
import net.prasenjit.identity.model.AuthorizationModel;
import net.prasenjit.identity.model.OAuthToken;
import net.prasenjit.identity.model.Profile;
import net.prasenjit.identity.model.openid.core.AuthorizeRequest;
import net.prasenjit.identity.repository.*;
import net.prasenjit.identity.security.GrantType;
import net.prasenjit.identity.security.OAuthError;
import net.prasenjit.identity.security.user.UserAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import java.time.Duration;
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
    private final UserConsentRepository userConsentRepository;

    public OAuthToken processPasswordGrant(Client client, String username, String password, String requestedScope) {
        if (!client.supportsGrant(GrantType.PASSWORD)) {
            throw new OAuthException("invalid_grant", "Unsupported grant");
        }
        Authentication authentication = new UsernamePasswordAuthenticationToken(username, password);
        try {
            authentication = authenticationManager.authenticate(authentication);
        } catch (BadCredentialsException e) {
            throw new OAuthException("access_denied", "user authentication failed", e);
        }
        String filteredScopes = filterScope(client.getApprovedScopes(), requestedScope);
        AccessToken accessToken = codeFactory.createAccessToken((User) authentication.getPrincipal(),
                client.getClientId(), client.getAccessTokenValidity(), filteredScopes, LocalDateTime.now());
        RefreshToken refreshToken = null;
        if (!client.supportsGrant(GrantType.REFRESH_TOKEN)) {
            refreshToken = codeFactory.createRefreshToken(client.getClientId(), username, filteredScopes,
                    LocalDateTime.now(), client.getRefreshTokenValidity(), false);
        }
        return codeFactory.createOAuthToken(accessToken, refreshToken, null);
    }

    public OAuthToken processClientCredentialsGrant(Client client, String scope) {
        if (!client.supportsGrant(GrantType.CLIENT_CREDENTIALS)) {
            throw new OAuthException("invalid_grant", "Unsupported grant");
        }
        String filteredScope = filterScope(client.getApprovedScopes(), scope);
        AccessToken accessToken = codeFactory.createAccessToken(client, client.getClientId(),
                client.getAccessTokenValidity(), filteredScope, LocalDateTime.now());
        return codeFactory.createOAuthToken(accessToken, null, null);
    }

    public AuthorizationModel validateAuthorizationGrant(Authentication authentication, AuthorizeRequest request,
                                                         AuthorizationModel authorizationModel) {
        Profile principal = extractPrincipal(authentication, Profile.class);
        authorizationModel = authorizationModel == null ? new AuthorizationModel() : authorizationModel;
        authorizationModel.setState(request.getState());
        authorizationModel.setProfile(principal);
        authorizationModel.setValid(false);
        authorizationModel.setResponseType(request.getResponse_type());
        authorizationModel.setRedirectUri(request.getRedirect_uri());
        authorizationModel.setNonce(request.getNonce());

        if (request.getClient_id() == null) {
            authorizationModel.setErrorCode(OAuthError.INVALID_REQUEST);
            authorizationModel.setErrorDescription("Client id not specified");
            return authorizationModel;
        }

        Optional<Client> client = clientRepository.findById(request.getClient_id());

        if (!client.isPresent()) {
            authorizationModel.setErrorCode(OAuthError.INVALID_REQUEST);
            authorizationModel.setErrorDescription("Provided clientId is invalid");
            return authorizationModel;
        } else {
            authorizationModel.setClient(client.get());
            if (request.getRedirect_uri() != null && !client.get().getRedirectUri().equals(request.getRedirect_uri())) {
                authorizationModel.setRedirectUri(client.get().getRedirectUri());
                authorizationModel.setErrorCode(OAuthError.INVALID_REQUEST);
                authorizationModel.setErrorDescription("Redirect URL doesn't match");
                return authorizationModel;
            }
            filterScopeToMap(client.get().getApprovedScopes(), request.getScope(), authorizationModel);
            if (principal != null) {
                Optional<UserConsent> consent = userConsentRepository.findById(new UserConsent.UserConsentPK(
                        principal.getUsername(), client.get().getClientId()));

                if (consent.isPresent()) {
                    String[] preApprovedScope = StringUtils.delimitedListToStringArray(consent.get().getScopes(), " ");
                    String[] toBeApprovedScopes = authorizationModel.getFilteredScopes().entrySet().stream()
                            .map(Map.Entry::getKey).collect(Collectors.toList()).toArray(new String[1]);
                    Arrays.sort(preApprovedScope);
                    Arrays.sort(toBeApprovedScopes);
                    if (Arrays.deepEquals(preApprovedScope, toBeApprovedScopes)) {
                        authorizationModel.setConsentRequired(false);
                    }
                }
            }

            if (authorizationModel.isOpenid()) {
                // handle prompt parameter for openid
                if (StringUtils.hasText(request.getPrompt())) {
                    String[] prompts = StringUtils.delimitedListToStringArray(request.getPrompt(), " ");
                    Arrays.sort(prompts);
                    boolean promptNone = Arrays.binarySearch(prompts, "none") > -1;
                    boolean promptLogin = Arrays.binarySearch(prompts, "login") > -1;
                    boolean promptConsent = Arrays.binarySearch(prompts, "consent") > -1;
                    if (promptNone && (promptLogin || promptConsent)) {
                        authorizationModel.setRedirectUri(client.get().getRedirectUri());
                        authorizationModel.setErrorCode(OAuthError.INVALID_REQUEST);
                        authorizationModel.setErrorDescription("Prompt none can not be combined with anything else");
                        return authorizationModel;
                    }
                    if (promptNone) {
                        if (principal == null) {
                            authorizationModel.setRedirectUri(client.get().getRedirectUri());
                            authorizationModel.setErrorCode(OAuthError.LOGIN_REQUIRED);
                            authorizationModel.setErrorDescription("User not logged in and prompt none is requested");
                            return authorizationModel;
                        }
                        if (authorizationModel.isConsentRequired()) {
                            authorizationModel.setErrorCode(OAuthError.INTERACTION_REQUIRED);
                            authorizationModel.setErrorDescription("User consent required");
                            return authorizationModel;
                        }
                    }
                    authorizationModel.setLoginRequired(promptLogin);
                    authorizationModel.setConsentRequired(promptConsent);
                    // handle prompt redirect
                } else if (principal == null) {
                    authorizationModel.setLoginRequired(true);
                }
                // handle max_age parameter for openid
                if (request.getMax_age() > 0) {
                    UserAuthenticationToken userAuthentication = (UserAuthenticationToken) authentication;
                    if (userAuthentication.getLoginTime().plusSeconds(request.getMax_age()).isBefore(LocalDateTime.now())) {
                        // redirect for re-login
                        authorizationModel.setLoginRequired(true);
                    }
                }
            }

            authorizationModel.setValid(true);
            return authorizationModel;

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
                List<String> approvedScope = authorizationModel.getFilteredScopes().entrySet().stream()
                        .filter(e ->
                                e.getValue() != null && e.getValue()
                        ).map(Map.Entry::getKey).collect(Collectors.toList());
                if (!StringUtils.hasText(authorizationModel.getRedirectUri())) {
                    authorizationModel.setRedirectUri(client.get().getRedirectUri());
                }

                // Save consent
                UserConsent userConsent = new UserConsent();
                userConsent.setUsername(authorizationModel.getProfile().getUsername());
                userConsent.setClientID(client.get().getClientId());
                userConsent.setApprovalDate(LocalDateTime.now());
                userConsent.setScopes(StringUtils.collectionToDelimitedString(approvedScope, " "));
                userConsentRepository.save(userConsent);

                if (authorizationModel.requireCodeResponse()) {
                    AuthorizationCode authorizationCode = codeFactory.createAuthorizationCode(
                            client.get().getClientId(), authorizationModel.getRedirectUri(),
                            StringUtils.collectionToDelimitedString(approvedScope, " "),
                            authorizationModel.getProfile().getUsername(), authorizationModel.getState(),
                            Duration.ofMinutes(10), authorizationModel.getLoginTime(), authorizationModel.isOpenid());
                    authorizationModel.setAuthorizationCode(authorizationCode);
                }
                if (authorizationModel.requireTokenResponse()) {
                    AccessToken accessToken = codeFactory.createAccessToken(authorizationModel.getProfile(),
                            client.get().getClientId(), client.get().getAccessTokenValidity(),
                            StringUtils.collectionToDelimitedString(approvedScope, " "),
                            authorizationModel.getLoginTime());
                    authorizationModel.setAccessToken(accessToken);
                }
                if (authorizationModel.requireIDTokenResponse()) {
                    String accessToken = null;
                    if (authorizationModel.getAccessToken() != null) {
                        accessToken = authorizationModel.getAccessToken().getAssessToken();
                    }
                    String accessCode = null;
                    if (authorizationModel.getAuthorizationCode() != null) {
                        accessCode = authorizationModel.getAuthorizationCode().getAuthorizationCode();
                    }
                    String idToken = codeFactory.createIDToken(authorizationModel.getProfile(),
                            authorizationModel.getLoginTime(), authorizationModel.getNonce(),
                            client.get().getClientId(), client.get().getAccessTokenValidity(),
                            approvedScope, accessToken, accessCode);
                    authorizationModel.setIdToken(idToken);
                }
                if (!(authorizationModel.requireCodeResponse() || authorizationModel.requireTokenResponse()
                        || authorizationModel.requireIDTokenResponse())) {
                    authorizationModel.setErrorCode(OAuthError.UNSUPPORTED_RESPONSE_TYPE);
                    authorizationModel.setErrorDescription("Invalid response type");
                    authorizationModel.setValid(false);
                }
                return authorizationModel;
            }
        }
        authorizationModel.setErrorCode(OAuthError.UNAUTHORIZED_REQUEST);
        authorizationModel.setErrorDescription("User has denied the access");
        authorizationModel.setValid(false);
        return authorizationModel;
    }

    public OAuthToken processAuthorizationCodeGrantToken(Client client, String code, String redirectUri,
                                                         String clientId) {
        if (client == null) {
            if (clientId == null) {
                throw new OAuthException("invalid_request", "non secure client must specify client_id parameter");
            }
            Optional<Client> optionalClient = clientRepository.findById(clientId);
            if (optionalClient.isPresent()) {
                if (optionalClient.get().isSecureClient()) {
                    throw new UnauthenticatedClientException("unauthorized_client", "Secure client must be authenticated");
                } else {
                    client = optionalClient.get();
                }
            } else {
                throw new OAuthException("invalid_request", "Client not found for client_id " + clientId);
            }
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
                                    AccessToken accessToken = codeFactory.createAccessToken(associatedUser.get(),
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
                        AccessToken accessToken = codeFactory.createAccessToken(userOptional.get(),
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